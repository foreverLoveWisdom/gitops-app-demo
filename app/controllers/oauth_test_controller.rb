require "signet/oauth_2/client"
require "google/apis/drive_v3"

class OauthTestController < ApplicationController
  REDIRECT_URI = "http://localhost:3000/auth/google_oauth2/callback"

  def authorize
    state = SecureRandom.hex(24)
    session["omniauth.state"] = state
    url = client.authorization_uri(prompt: "consent", state: state).to_s
    render json: { authorize_url: url }
  end

  def callback
    if params[:state].to_s.empty? || !secure_compare(params[:state], session.delete("omniauth.state").to_s)
      render json: { error: "CSRF detected" }, status: :unauthorized
      return
    end

    oauth_client = client
    oauth_client.code = params[:code]
    oauth_client.fetch_access_token!

    drive_service = Google::Apis::DriveV3::DriveService.new
    drive_service.authorization = oauth_client
    file_list = drive_service.list_files

    render json: {
      access_token: oauth_client.access_token,
      refresh_token: oauth_client.refresh_token,
      drive_files: file_list.files.map { |f| { id: f.id, name: f.name, mime_type: f.mime_type } }
    }
  end

  def failure
    render json: { error: params[:error] }, status: :unauthorized
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
      scope: "email profile https://www.googleapis.com/auth/drive.readonly"
    )
  end
end
