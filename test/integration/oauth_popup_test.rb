require "test_helper"

class OauthPopupTest < ActionDispatch::IntegrationTest
  AUTHORIZE = "/auth/google_drive/authorize".freeze
  CALLBACK = "/auth/google_drive/callback".freeze

  setup do
    ENV["GOOGLE_CLIENT_ID"] ||= "test-client-id"
    ENV["GOOGLE_CLIENT_SECRET"] ||= "test-client-secret"
  end

  test "callback reports success when Google accepts the code" do
    get AUTHORIZE
    stub_exchange

    get CALLBACK, params: { state: google_params["state"], code: "auth-code" }

    assert_equal "success", fe_params["status"]
  end

  # RFC 7636 section 4.1: 43-128 characters. The verifier is lost if it fails to survive the round trip.
  test "callback exchanges the code with a verifier that survived the round trip to Google" do
    get AUTHORIZE
    seen = stub_exchange

    get CALLBACK, params: { state: google_params["state"], code: "auth-code" }

    assert_operator seen[:verifier].to_s.length, :>=, 43
  end

  test "callback reports exchange_failed when Google rejects the code" do
    get AUTHORIZE
    stub_exchange(error: Signet::AuthorizationError.new("invalid_grant"))

    get CALLBACK, params: { state: google_params["state"], code: "bad" }

    assert_fe_error "exchange_failed"
  end

  test "callback logs the failing step and Google's reason when the exchange fails" do
    get AUTHORIZE
    stub_exchange(error: Signet::AuthorizationError.new("invalid_grant"))

    log = capture_log { get CALLBACK, params: { state: google_params["state"], code: "bad-code" } }

    assert_match(/token_exchange.*invalid_grant/, log)
  end

  test "callback never logs the authorization code" do
    get AUTHORIZE
    stub_exchange(error: Signet::AuthorizationError.new("invalid_grant"))

    log = capture_log { get CALLBACK, params: { state: google_params["state"], code: "bad-code" } }

    assert_not_includes log, "bad-code"
  end

  test "callback never logs the state" do
    get AUTHORIZE
    state = google_params["state"]
    stub_exchange

    log = capture_log { get CALLBACK, params: { state: state, code: "auth-code" } }

    assert_not_includes log, state
  end

  test "authorize keeps a code param visible, since only the callback carries secrets" do
    log = capture_log { get AUTHORIZE, params: { code: "visible-elsewhere" } }

    assert_includes log, "visible-elsewhere"
  end

  private

  def capture_log
    io = StringIO.new
    original = ActionController::Base.logger
    ActionController::Base.logger = ActiveSupport::Logger.new(io)
    yield
    io.string
  ensure
    ActionController::Base.logger = original
  end

  # Replaces the network call to Google's token endpoint, the only boundary the callback crosses.
  def stub_exchange(error: nil)
    klass = Google::Auth::UserAuthorizer
    original = klass.instance_method(:get_and_store_credentials_from_code)
    seen = {}
    klass.define_method(:get_and_store_credentials_from_code) do |options|
      seen[:code] = options[:code]
      seen[:verifier] = @code_verifier
      raise error if error
    end
    @restore_exchange = -> { klass.define_method(:get_and_store_credentials_from_code, original) }
    seen
  end

  teardown { @restore_exchange&.call }

  def google_params
    Rack::Utils.parse_query(URI(response.location).query)
  end

  def fe_params
    Rack::Utils.parse_query(URI(response.location).query)
  end

  def assert_fe_error(reason)
    assert_equal "localhost:3001", URI(response.location).authority
    assert_equal({ "status" => "error", "reason" => reason }, fe_params)
  end
end
