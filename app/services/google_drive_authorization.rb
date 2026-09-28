# One browser's authorization attempt: start it, then finish it exactly once.
class GoogleDriveAuthorization
  # State and verifier live and die together, so they share one session entry.
  ATTEMPT_KEY = 'google_drive.attempt'.freeze
  # Anyone can call the callback URL, so an unknown error value must never reach the FE.
  # Only the authorization error codes of RFC 6749 section 4.1.2.1 pass through.
  AUTHORIZATION_ERROR_CODES = %w[
    invalid_request unauthorized_client access_denied unsupported_response_type
    invalid_scope server_error temporarily_unavailable
  ].freeze

  # state: RFC 6749 section 10.12, a random value bound to this browser's session.
  # code_verifier: the PKCE secret that must survive the round trip to Google.
  Attempt = Data.define(:state, :code_verifier)

  # @param session [#[], #[]=, #delete] the browser's session
  # @param authorizer [GoogleAuthorizer] the boundary to Google
  def initialize(session:, authorizer:)
    @session = session
    @authorizer = authorizer
  end

  # @return [String] the Google URL to send the browser to
  # ponytail: state has no expiry, lives as long as the session; upgrade when an
  # abandoned popup leaving a valid state in the session becomes a concern.
  def start
    # Not the gem's generator: it can return fewer than the 43 characters RFC 7636 requires.
    attempt = Attempt.new(state: SecureRandom.urlsafe_base64(32), code_verifier: SecureRandom.urlsafe_base64(64))
    @session[ATTEMPT_KEY] = attempt.to_h.stringify_keys
    @authorizer.authorization_url(state: attempt.state, code_verifier: attempt.code_verifier)
  end

  # @param state [String, nil] state echoed back in the callback URL
  # @param code [String, nil] authorization code from the callback URL
  # @param error [String, nil] authorization error from the callback URL
  # @return [OauthOutcome::Approved, OauthOutcome::Refused]
  def finish(state:, code:, error:)
    attempt = take_attempt
    case check(attempt, state: state, code: code, error: error)
    in OauthOutcome::Refused => refused then refused
    in OauthOutcome::Approved then @authorizer.exchange(code: code, code_verifier: attempt.code_verifier)
    end
  end

  private

  # A replayed callback URL must fail, so the attempt is removed whatever the outcome.
  def take_attempt
    stored = @session.delete(ATTEMPT_KEY)
    stored && Attempt.new(state: stored['state'], code_verifier: stored['code_verifier'])
  end

  def check(attempt, state:, code:, error:)
    return refuse('csrf_detected') unless state_matches?(attempt, state)
    # A denial carries an error and no code, so read the error first.
    return refuse(AUTHORIZATION_ERROR_CODES.include?(error.to_s) ? error.to_s : 'invalid_request') if error.present?
    return refuse('exchange_failed') if code.blank?

    OauthOutcome::Approved.new
  end

  def state_matches?(attempt, sent)
    return false unless attempt && sent.is_a?(String)

    ActiveSupport::SecurityUtils.secure_compare(sent, attempt.state)
  end

  def refuse(reason) = OauthOutcome::Refused.new(reason: reason)
end
