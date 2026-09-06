class StatusController < ApplicationController
  def show
    @checked_at = Time.current

    raw = `kubectl get application nginx-demo -n argocd -o json 2>&1`
    @app = JSON.parse(raw)

    pods_raw = `kubectl get pods -n default -l app=gitops-app-demo -o json 2>&1`
    @pods = JSON.parse(pods_raw)["items"]
  rescue JSON::ParserError
    @error = raw
  end
end
