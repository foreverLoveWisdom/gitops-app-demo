class StatusController < ApplicationController
  def show
    raw = `kubectl get application nginx-demo -n argocd -o json 2>&1`
    @app = JSON.parse(raw)
  rescue JSON::ParserError
    @error = raw
  end
end
