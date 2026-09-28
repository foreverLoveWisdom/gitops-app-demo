# Hides extra params from the request log for chosen paths only. Rails reads the filter from
# the request env, so the change lasts for that one request and the app-wide list stays as is.
class ScopedParameterFilter
  # @param app [#call] the next Rack app
  # @param rules [Hash{String => Array<Regexp, Symbol>}] request path to the extra params to hide
  def initialize(app, rules)
    @app = app
    @rules = rules
  end

  # @param env [Hash] the Rack env
  # @return [Array] the Rack response
  def call(env)
    extra = @rules[env['PATH_INFO']]
    env['action_dispatch.parameter_filter'] = Array(env['action_dispatch.parameter_filter']) + extra if extra
    @app.call(env)
  end
end

# The callback carries the authorization code (a spendable credential) and state (the CSRF secret).
# Exact match, so error_code and the like stay visible. First in the stack, before any request logger.
Rails.application.config.middleware.insert_before(
  0, ScopedParameterFilter, '/auth/google_drive/callback' => [/\Acode\z/, /\Astate\z/]
)
