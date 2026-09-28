require 'googleauth'

class OauthPopupController < ApplicationController
  # Must match the redirect URI registered in the Google console exactly.
  REDIRECT_URI = 'http://localhost:3000/auth/google_drive/callback'
  FE_LANDING_URI = 'http://localhost:3001/oauth-landing'
  # The PKCE verifier must survive the round trip to Google, so it waits in the session.
  CODE_VERIFIER_KEY = 'google_drive.code_verifier'.freeze
  # RFC 6749 section 10.12: a random value bound to this browser's session, sent as state.
  STATE_KEY = 'google_drive.state'.freeze
  # The token store needs a user key. The prototype has no login, so every run shares one.
  PROTOTYPE_USER_ID = 'prototype-user'.freeze
  # Anyone can call the callback URL, so an unknown error value must never reach the FE.
  # Only the authorization error codes of RFC 6749 section 4.1.2.1 pass through.
  AUTHORIZATION_ERROR_CODES = %w[
    invalid_request unauthorized_client access_denied unsupported_response_type
    invalid_scope server_error temporarily_unavailable
  ].freeze

  # googleauth saves the access token and refresh token through a token store after each
  # code exchange, and again after each token refresh. This prototype only proves the
  # popup flow, so the store throws everything away.
  # ponytail: discards tokens, upgrade when the app must call Google APIs later (use a
  # database-backed store and encrypt the refresh token).
  class DiscardingTokenStore
    def load(_user_id) = nil
    def store(_user_id, _token); end
    def delete(_user_id); end
  end

  # ponytail: state has no expiry, lives as long as the session; upgrade when an
  # abandoned popup leaving a valid state in the session becomes a concern.
  def authorize
    # Not the gem's generator: it can return fewer than the 43 characters RFC 7636 requires.
    code_verifier = SecureRandom.urlsafe_base64(64)
    state = SecureRandom.urlsafe_base64(32)
    session[CODE_VERIFIER_KEY] = code_verifier
    session[STATE_KEY] = state
    redirect_to authorizer(code_verifier).get_authorization_url(state: state), allow_other_host: true
  end

  def callback
    reason = failure_reason
    return redirect_to_fe(status: 'error', reason: reason) if reason

    case exchange_code
    in [:ok]
      # ponytail: fake email, upgrade when the FE must show the real Google account.
      redirect_to_fe(status: 'success', account_email: 'test@example.com')
    in [:error, step, detail]
      # The FE only gets a fixed reason. Google's own message stays in this log.
      logger.warn("oauth callback failed at #{step}: #{detail}")
      redirect_to_fe(status: 'error', reason: 'exchange_failed')
    end
  ensure
    # A replayed callback URL must fail, so state and verifier are single-use whatever the outcome.
    session.delete(STATE_KEY)
    session.delete(CODE_VERIFIER_KEY)
  end

  private

  # Failure is a returned value naming the step, so the caller decides what to show and log.
  # Never put the code or verifier in detail: it goes to the log.
  def exchange_code
    authorizer(session[CODE_VERIFIER_KEY]).get_and_store_credentials_from_code(
      user_id: PROTOTYPE_USER_ID, code: params[:code], base_url: REDIRECT_URI
    )
    [:ok]
  rescue Signet::AuthorizationError, Signet::ParseError => e
    [:error, :token_exchange, "#{e.class}: #{e.message}"]
  end

  def failure_reason
    return 'csrf_detected' unless state_valid?

    # A denial carries an error and no code, so read the error first.
    error = params[:error].to_s
    return AUTHORIZATION_ERROR_CODES.include?(error) ? error : 'invalid_request' unless error.empty?

    'exchange_failed' if params[:code].blank?
  end

  def state_valid?
    expected = session[STATE_KEY]
    sent = params[:state]
    expected.present? && sent.is_a?(String) && ActiveSupport::SecurityUtils.secure_compare(sent, expected)
  end

  def redirect_to_fe(query)
    redirect_to "#{FE_LANDING_URI}?#{query.to_query}", allow_other_host: true
  end

  # googleauth always adds access_type=offline, approval_prompt=force and
  # include_granted_scopes=true. Scopes granted earlier therefore carry over to this grant.
  def authorizer(code_verifier)
    Google::Auth::UserAuthorizer.new(
      Google::Auth::ClientId.new(ENV['GOOGLE_CLIENT_ID'], ENV['GOOGLE_CLIENT_SECRET']),
      %w[email profile],
      DiscardingTokenStore.new,
      callback_uri: REDIRECT_URI,
      code_verifier: code_verifier
    )
  end
end
