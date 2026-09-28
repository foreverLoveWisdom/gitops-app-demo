require "test_helper"

class GoogleDriveAuthorizationTest < ActiveSupport::TestCase
  # Stands in for Google: records what it is asked and answers with a chosen outcome.
  class FakeAuthorizer
    attr_reader :urls, :exchanges

    def initialize(outcome: OauthOutcome::Approved.new)
      @outcome = outcome
      @urls = []
      @exchanges = []
    end

    def authorization_url(state:, code_verifier:)
      @urls << { state: state, code_verifier: code_verifier }
      "https://google.test/consent"
    end

    def exchange(code:, code_verifier:)
      @exchanges << { code: code, code_verifier: code_verifier }
      @outcome
    end
  end

  setup do
    @session = {}
    @authorizer = FakeAuthorizer.new
    @authorization = GoogleDriveAuthorization.new(session: @session, authorizer: @authorizer)
  end

  test "start hands back the URL Google should show" do
    assert_equal "https://google.test/consent", @authorization.start
  end

  test "start sends a state that carries no data an attacker could edit" do
    @authorization.start

    assert_opaque(issued[:state])
  end

  test "start creates a verifier long enough for PKCE" do
    @authorization.start

    assert_operator issued[:code_verifier].length, :>=, 43
  end

  test "finish approves the callback that carries the state start issued" do
    @authorization.start

    assert_equal OauthOutcome::Approved.new, finish(state: issued[:state])
  end

  test "finish exchanges the code with the verifier start created" do
    @authorization.start

    finish(state: issued[:state], code: "auth-code")

    assert_equal [{ code: "auth-code", code_verifier: issued[:code_verifier] }], @authorizer.exchanges
  end

  test "finish refuses a state start never issued, so a forged callback never reaches Google" do
    @authorization.start

    assert_refused "csrf_detected", finish(state: "forged")
    assert_empty @authorizer.exchanges
  end

  test "finish refuses a callback when no attempt was started, even if the URL has no state either" do
    assert_refused "csrf_detected", finish(state: nil)
  end

  test "finish accepts the state only once, so a replayed callback fails" do
    @authorization.start
    finish(state: issued[:state])

    assert_refused "csrf_detected", finish(state: issued[:state])
  end

  test "finish removes the attempt even when it refuses, so a failed callback cannot be retried" do
    @authorization.start
    finish(state: "forged")

    assert_refused "csrf_detected", finish(state: issued[:state])
  end

  test "finish passes a denial from Google through to the FE" do
    @authorization.start

    assert_refused "access_denied", finish(state: issued[:state], code: nil, error: "access_denied")
  end

  test "finish replaces an error value Google never defined, so nothing attacker-written reaches the FE" do
    @authorization.start

    assert_refused "invalid_request", finish(state: issued[:state], code: nil, error: "<script>x</script>")
  end

  test "finish refuses a callback with no code without calling Google" do
    @authorization.start

    assert_refused "exchange_failed", finish(state: issued[:state], code: nil)
    assert_empty @authorizer.exchanges
  end

  test "finish returns Google's refusal so the caller can log why" do
    refusal = OauthOutcome::Refused.new(reason: "exchange_failed", step: :token_exchange, detail: "invalid_grant")
    authorization = GoogleDriveAuthorization.new(session: @session, authorizer: FakeAuthorizer.new(outcome: refusal))
    authorization.start

    assert_equal refusal, authorization.finish(state: @session.fetch(GoogleDriveAuthorization::ATTEMPT_KEY)["state"],
                                               code: "bad", error: nil)
  end

  private

  def issued = @authorizer.urls.last

  def finish(state:, code: "auth-code", error: nil)
    @authorization.finish(state: state, code: code, error: error)
  end

  def assert_refused(reason, outcome)
    assert_equal reason, outcome.reason
  end

  # JSON or a URL would mean the state carries data an attacker can edit.
  def assert_opaque(state)
    assert_operator state.length, :>=, 32
    assert_raises(JSON::ParserError) { JSON.parse(state) }
  end
end
