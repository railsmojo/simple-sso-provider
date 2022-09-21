class Client < ActiveRecord::Base

  before_validation :set_attributes

  validates :name, :presence => true

  # Check whether a Client exists by app_id and app_secret
  def self.authenticate(app_id, app_secret)
    where(["app_id = ? AND app_secret = ?", app_id, app_secret]).first
  end

  private
    def set_attributes
      if new_record?
        generate_app_id!
        generate_app_secret!
      end
    end

    def generate_app_id!
      begin
        self.app_id = SecureRandom.hex
      end while self.class.exists?(app_id: app_id)
    end

    def generate_app_secret!
      begin
        self.app_secret = SecureRandom.hex
      end while self.class.exists?(app_secret: app_secret)
    end
end
