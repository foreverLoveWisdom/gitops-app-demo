require "googleauth"
require "googleauth/web_user_authorizer"

class OauthPopupController < ApplicationController
  # Must match the redirect URI registered in the Google console exactly.
  REDIRECT_URI = "http://localhost:3000/auth/google_drive/callback"
  FE_LANDING_URI = "http://localhost:3001/oauth-landing"
  # The PKCE verifier must survive the round trip to Google, so it waits in the session.
  CODE_VERIFIER_KEY = "google_drive.code_verifier".freeze
  XSRF_KEY = Google::Auth::WebUserAuthorizer::XSRF_KEY
  # The token store needs a user key. The prototype has no login, so every run shares one.
  PROTOTYPE_USER_ID = "prototype-user".freeze
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
    session[CODE_VERIFIER_KEY] = code_verifier
    # The gem puts this URL inside state. The callback ignores it, because anyone can edit state.
    url = authorizer(code_verifier).get_authorization_url(request: request, redirect_to: FE_LANDING_URI)
    redirect_to url, allow_other_host: true
  end

  def callback
    reason = failure_reason
    return redirect_to_fe(status: "error", reason: reason) if reason

    authorizer(session[CODE_VERIFIER_KEY]).handle_auth_callback(PROTOTYPE_USER_ID, request)
    # ponytail: fake email, upgrade when the FE must show the real Google account.
    redirect_to_fe(status: "success", account_email: "test@example.com")
  rescue Google::Auth::AuthorizationError, Google::Auth::ParseError
    redirect_to_fe(status: "error", reason: "exchange_failed")
  ensure
    # A replayed callback URL must fail, so state and verifier are single-use whatever the outcome.
    session.delete(XSRF_KEY)
    session.delete(CODE_VERIFIER_KEY)
  end

  private

  def failure_reason
    return "csrf_detected" unless state_valid?

    # Read a denial here, before the gem. When the user denies, Google sends no code,
    # and the gem reports "missing code" instead of the error name.
    error = params[:error].to_s
    return if error.empty?

    AUTHORIZATION_ERROR_CODES.include?(error) ? error : "invalid_request"
  end

  # The gem's own check passes when both sides are nil (no state, no session token) and
  # uses a plain string compare. Check first, so a missing token never validates.
  def state_valid?
    expected = session[XSRF_KEY]
    sent = JSON.parse(params[:state].to_s)["session_id"]
    expected.present? && sent.is_a?(String) && ActiveSupport::SecurityUtils.secure_compare(sent, expected)
  rescue JSON::ParserError, TypeError
    false
  end

  def redirect_to_fe(query)
    redirect_to "#{FE_LANDING_URI}?#{query.to_query}", allow_other_host: true
  end

  # googleauth always adds access_type=offline, approval_prompt=force and
  # include_granted_scopes=true. Scopes granted earlier therefore carry over to this grant.
  def authorizer(code_verifier)
    Google::Auth::WebUserAuthorizer.new(
      Google::Auth::ClientId.new(ENV["GOOGLE_CLIENT_ID"], ENV["GOOGLE_CLIENT_SECRET"]),
      %w[email profile],
      DiscardingTokenStore.new,
      callback_uri: REDIRECT_URI,
      code_verifier: code_verifier
    )
  end
end
