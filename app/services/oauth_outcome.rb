# What a finished authorization step means. Callers match on the type and read named fields,
# so nobody has to remember what a slot in a returned array stands for.
module OauthOutcome
  Approved = Data.define

  # reason is safe to show the FE. step and detail are for our log only.
  Refused = Data.define(:reason, :step, :detail) do
    def initialize(reason:, step: nil, detail: nil) = super

    def to_s = [reason, step, detail].compact.join(' | ')
  end
end
