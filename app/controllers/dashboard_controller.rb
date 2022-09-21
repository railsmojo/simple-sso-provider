class DashboardController < ApplicationController
  before_action :authenticate_user!
  
  def index
    @users = User.order("created_at desc")
  end
end
