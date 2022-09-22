class JsonWebToken
  def self.encode(payload)
    # JWT.encode(payload, Rails.application.secrets.jwt_key_base, 'HS512')
    JWT.encode(payload, '78a7s87a8s7a87878887c787c8787878d78d787144534x343s')
  end

  def self.decode(token)
    # return HashWithIndifferentAccess.new(JWT.decode(token, Rails.application.secrets.jwt_key_base, true, { :algorithm => 'HS512'})[0])
    return HashWithIndifferentAccess.new(JWT.decode(token, '78a7s87a8s7a87878887c787c8787878d78d787144534x343s', true)[0])
  rescue
    nil
  end
end
