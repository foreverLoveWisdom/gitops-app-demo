require "test_helper"

class OauthPopupTest < ActionDispatch::IntegrationTest
  AUTHORIZE = "/auth/google_drive/authorize".freeze
  CALLBACK = "/auth/google_drive/callback".freeze

  setup do
    ENV["GOOGLE_CLIENT_ID"] ||= "test-client-id"
    ENV["GOOGLE_CLIENT_SECRET"] ||= "test-client-secret"
  end

  test "authorize sends a state that carries no data an attacker could edit" do
    get AUTHORIZE

    assert_opaque_state google_params["state"]
  end

  test "callback accepts the state issued by authorize" do
    get AUTHORIZE

    get CALLBACK, params: { state: google_params["state"], error: "access_denied" }

    assert_fe_error "access_denied"
  end

  test "callback rejects a state that authorize never issued" do
    get AUTHORIZE

    get CALLBACK, params: { state: "forged", error: "access_denied" }

    assert_fe_error "csrf_detected"
  end

  test "callback rejects a request when neither the browser nor the URL holds a state" do
    get CALLBACK, params: { error: "access_denied" }

    assert_fe_error "csrf_detected"
  end

  test "callback state is single-use" do
    get AUTHORIZE
    state = google_params["state"]
    get CALLBACK, params: { state: state, error: "access_denied" }

    get CALLBACK, params: { state: state, error: "access_denied" }

    assert_fe_error "csrf_detected"
  end

  test "callback replaces an unknown error value before it reaches the FE" do
    get AUTHORIZE

    get CALLBACK, params: { state: google_params["state"], error: "<script>x</script>" }

    assert_fe_error "invalid_request"
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

  test "callback reports exchange_failed when the code is missing" do
    get AUTHORIZE
    seen = stub_exchange

    get CALLBACK, params: { state: google_params["state"] }

    assert_fe_error "exchange_failed"
    assert_empty seen, "Google must not be called without a code"
  end

  test "callback reports exchange_failed when Google rejects the code" do
    get AUTHORIZE
    stub_exchange(error: Signet::AuthorizationError.new("invalid_grant"))

    get CALLBACK, params: { state: google_params["state"], code: "bad" }

    assert_fe_error "exchange_failed"
  end

  private

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

  # JSON or a URL would mean the state carries data an attacker can edit.
  def assert_opaque_state(state)
    assert_operator state.to_s.length, :>=, 32
    assert_raises(JSON::ParserError) { JSON.parse(state) }
  end
end
