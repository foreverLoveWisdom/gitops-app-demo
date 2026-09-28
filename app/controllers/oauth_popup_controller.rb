require "googleauth"
require "googleauth/web_user_authorizer"

class OauthPopupController < ApplicationController
  REDIRECT_URI = "http://localhost:3000/auth/google_drive/callback"
  FE_LANDING_URI = "http://localhost:3001/oauth-landing"
  VERIFIER_KEY = "google_drive.code_verifier".freeze
  XSRF_KEY = Google::Auth::WebUserAuthorizer::XSRF_KEY
  PROTOTYPE_USER_ID = "prototype-user".freeze
  # RFC 6749 §4.1.2.1 — anything else is dropped, never echoed to the FE.
  OAUTH_ERROR_CODES = %w[
    invalid_request unauthorized_client access_denied unsupported_response_type
    invalid_scope server_error temporarily_unavailable
  ].freeze

  # ponytail: discards credentials, prototype persists nothing by design; upgrade when
  # Coffret stores real credentials (swap in a DB-backed token store).
  class DiscardingTokenStore
    def load(_user_id) = nil
    def store(_user_id, _token); end
    def delete(_user_id); end
  end

  # ponytail: state has no expiry, lives as long as the session; upgrade when an
  # abandoned popup leaving a valid state in the session becomes a concern.
  def authorize
    verifier = SecureRandom.urlsafe_base64(64) # 86 chars, RFC 7636 needs 43-128
    session[VERIFIER_KEY] = verifier
    url = authorizer(verifier).get_authorization_url(request: request, redirect_to: FE_LANDING_URI)
    redirect_to url, allow_other_host: true
  end

  def callback
    reason = failure_reason
    return redirect_to_fe(status: "error", reason: reason) if reason

    authorizer(session[VERIFIER_KEY]).handle_auth_callback(PROTOTYPE_USER_ID, request)
    redirect_to_fe(status: "success", account_email: "test@example.com")
  rescue Google::Auth::AuthorizationError, Google::Auth::ParseError
    redirect_to_fe(status: "error", reason: "exchange_failed")
  ensure
    # single use: burn state + verifier whatever the outcome
    session.delete(XSRF_KEY)
    session.delete(VERIFIER_KEY)
  end

  private

  def failure_reason
    return "csrf_detected" unless state_valid?

    error = params[:error].to_s
    return if error.empty?

    OAUTH_ERROR_CODES.include?(error) ? error : "invalid_request"
  end

  # The gem's own check passes when both sides are nil (no state, no session token) and
  # compares with `!=`; guard first so a missing token can never validate.
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
