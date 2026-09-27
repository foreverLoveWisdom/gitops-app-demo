require "signet/oauth_2/client"

class OauthPopupController < ApplicationController
  REDIRECT_URI = "http://localhost:3000/auth/google_drive/callback"
  FE_LANDING_URI = "http://localhost:3001/oauth-landing"

  def authorize
    state = SecureRandom.hex(24)
    session["omniauth.state"] = state
    redirect_to client.authorization_uri(prompt: "consent", state: state).to_s, allow_other_host: true
  end

  def callback
    if params[:error].present?
      redirect_to "#{FE_LANDING_URI}?status=error&reason=#{params[:error]}", allow_other_host: true
      return
    end

    if params[:state].to_s.empty? || !secure_compare(params[:state], session.delete("omniauth.state").to_s)
      redirect_to "#{FE_LANDING_URI}?status=error&reason=csrf_detected", allow_other_host: true
      return
    end

    oauth_client = client
    oauth_client.code = params[:code]
    oauth_client.fetch_access_token!

    # Real flow upserts google_drive_credentials here. Skipped on purpose —
    # this test only proves the popup/postMessage mechanic, not persistence.
    redirect_to "#{FE_LANDING_URI}?status=success&account_email=test%40example.com", allow_other_host: true
  rescue Google::Auth::AuthorizationError, Signet::AuthorizationError
    redirect_to "#{FE_LANDING_URI}?status=error&reason=exchange_failed", allow_other_host: true
  end

  private

  def secure_compare(a, b)
    ActiveSupport::SecurityUtils.secure_compare(a, b)
  end

  def client
    Signet::OAuth2::Client.new(
      authorization_uri: "https://accounts.google.com/o/oauth2/auth",
      token_credential_uri: "https://oauth2.googleapis.com/token",
      client_id: ENV["GOOGLE_CLIENT_ID"],
      client_secret: ENV["GOOGLE_CLIENT_SECRET"],
      redirect_uri: REDIRECT_URI,
      scope: "email profile"
    )
  end
end
