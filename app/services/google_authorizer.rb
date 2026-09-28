require 'googleauth'

# The only code that talks to the googleauth gem. Everything else sees plain values.
class GoogleAuthorizer
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

  # @param client_id [String] Google OAuth client id
  # @param client_secret [String] Google OAuth client secret
  # @param redirect_uri [String] callback URL, exactly as registered in the Google console
  # @param user_id [String] key the token store files credentials under
  # @param scopes [Array<String>] scopes to request
  def initialize(client_id:, client_secret:, redirect_uri:, user_id:, scopes: %w[email profile])
    @client_id = Google::Auth::ClientId.new(client_id, client_secret)
    @redirect_uri = redirect_uri
    @user_id = user_id
    @scopes = scopes
  end

  # @param state [String] opaque CSRF value Google echoes back
  # @param code_verifier [String] PKCE secret; only its hash goes to Google
  # @return [String] the Google URL to send the browser to
  def authorization_url(state:, code_verifier:)
    gem_authorizer(code_verifier).get_authorization_url(state: state)
  end

  # Never put the code or verifier in detail: it goes to the log.
  # @param code [String] authorization code from the callback
  # @param code_verifier [String] the PKCE secret behind the challenge sent earlier
  # @return [OauthOutcome::Approved, OauthOutcome::Refused]
  def exchange(code:, code_verifier:)
    gem_authorizer(code_verifier).get_and_store_credentials_from_code(
      user_id: @user_id, code: code, base_url: @redirect_uri
    )
    OauthOutcome::Approved.new
  rescue Signet::AuthorizationError, Signet::ParseError => e
    OauthOutcome::Refused.new(reason: 'exchange_failed', step: :token_exchange, detail: "#{e.class}: #{e.message}")
  end

  private

  # googleauth always adds access_type=offline, approval_prompt=force and
  # include_granted_scopes=true. Scopes granted earlier therefore carry over to this grant.
  def gem_authorizer(code_verifier)
    Google::Auth::UserAuthorizer.new(
      @client_id, @scopes, DiscardingTokenStore.new,
      callback_uri: @redirect_uri, code_verifier: code_verifier
    )
  end
end
