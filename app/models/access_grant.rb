class AccessGrant < ActiveRecord::Base
  belongs_to :user
  belongs_to :client

  before_create :generate_tokens

  # Generate random tokens
  def generate_tokens
    self.code = SecureRandom.hex(16)
    self.access_token = SecureRandom.hex(16)
    self.refresh_token = SecureRandom.hex(16)
  end

  def self.prune!
    where("created_at < ?", 3.days.ago).delete_all
  end

  def redirect_uri_for(redirect_uri)
    if redirect_uri =~ /\?/
      redirect_uri + "&code=#{code}&response_type=code&state=#{state}"
    else
      redirect_uri + "?code=#{code}&response_type=code&state=#{state}"
    end
  end

  def self.authenticate(code, application_id)
    AccessGrant.where("code = ? AND client_id = ?", code, application_id).first
  end

  # Note: This is currently configured through devise, and matches the AuthController access token life
  def start_expiry_period!
    self.update_attribute(:access_token_expires_at, Time.now + Devise.timeout_in)
  end
end
