class OauthPopupController < ApplicationController
  # Must match the redirect URI registered in the Google console exactly.
  REDIRECT_URI = 'http://localhost:3000/auth/google_drive/callback'.freeze
  FE_LANDING_URI = 'http://localhost:3001/oauth-landing'.freeze
  # The token store needs a user key. The prototype has no login, so every run shares one.
  PROTOTYPE_USER_ID = 'prototype-user'.freeze

  def authorize
    redirect_to authorization.start, allow_other_host: true
  end

  def callback
    authorization.finish(state: params[:state], code: params[:code], error: params[:error])
    # ponytail: fake email, upgrade when the FE must show the real Google account.
    redirect_to_fe(status: 'success', account_email: 'test@example.com')
  rescue GoogleDriveAuthorization::Refused => e
    logger.warn("oauth callback refused: #{e.reason}")
    redirect_to_fe(status: 'error', reason: e.reason)
  end

  private

  def authorization
    GoogleDriveAuthorization.new(
      session: session,
      authorizer: GoogleAuthorizer.new(
        client_id: ENV['GOOGLE_CLIENT_ID'], client_secret: ENV['GOOGLE_CLIENT_SECRET'],
        redirect_uri: REDIRECT_URI, user_id: PROTOTYPE_USER_ID, logger: logger
      )
    )
  end

  def redirect_to_fe(query)
    redirect_to "#{FE_LANDING_URI}?#{query.to_query}", allow_other_host: true
  end
end
