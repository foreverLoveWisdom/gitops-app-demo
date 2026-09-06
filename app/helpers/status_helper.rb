module StatusHelper
  ICONS = {
    "Synced" => "✅", "Healthy" => "✅", "Running" => "✅",
    "OutOfSync" => "⚠️", "Progressing" => "⏳", "Pending" => "⏳",
    "Degraded" => "❌", "Missing" => "❌", "Unknown" => "❌"
  }.freeze

  def status_icon(value)
    return "" if value.nil?
    ICONS.fetch(value, "❌")
  end
end
