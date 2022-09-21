class AuthController < ApplicationController
  # This is our new function that comes before Devise's one
  before_action :authenticate_user_from_token!, :except => [:access_token]

  # before_action :authenticate_user!, :except => [:access_token]
  before_action :custom_authentication, :except => [:access_token]

  skip_before_action :verify_authenticity_token, :only => [:access_token]

  def authorize
    # Note: this method will be called when the user
    # is logged into the provider
    #
    # So we're essentially granting him access to our
    # system by generating certain tokens and then
    # redirecting him back to the params[:redirect_uri]
    # with a random code and the params[:state]


    AccessGrant.prune!
    create_hash = {
      client: application,
      state: params[:state]
    }
    access_grant = current_user.access_grants.create(create_hash)
    redirect_to access_grant.redirect_uri_for(params[:redirect_uri])
  end

  # POST
  def access_token
    application = Client.authenticate(params[:client_id], params[:client_secret])

    if application.nil?
      render :json => {:error => "Could not find application"}
      return
    end

    access_grant = AccessGrant.authenticate(params[:code], application.id)
    if access_grant.nil?
      render :json => {:error => "Could not authenticate access code"}
      return
    end

    access_grant.start_expiry_period!
    jwt = JsonWebToken.encode({ access_token: access_grant.access_token, user: access_grant.user })
    render :json => {:access_token => jwt, :refresh_token => access_grant.refresh_token, :expires_in => Devise.timeout_in.to_i}
  end

  def user
    # profile = Profile.find_by_profiler_id(current_user.id)
    hash = {
      provider: 'sso',
      id: current_user.id.to_s,
      info: {
         email: current_user.email,
      },
      extra: {
        first_name: 'Anonymous',
        last_name: 'User'
      }
    }

    render :json => hash.to_json
  end

  protected

  def application
    @application ||= Client.find_by_app_id(params[:client_id])
  end

  private

  def authenticate_user_from_token!
    if params[:oauth_token]
      jwt_token = JsonWebToken.decode(params[:oauth_token])
      if jwt_token
        access_grant = AccessGrant.where(access_token: jwt_token[:access_token]).take
        if access_grant.user
          # Devise sign in
          sign_in access_grant.user
        end
      else
        render :json => {:error => "Invalid credentials"}
      end
    end
  end

  def custom_authentication
    if params[:redirect_uri] and params[:redirect_uri].include? 'type'
      type = params[:redirect_uri].split("type=")[1]
      redirect_to new_user_registration_path(type: type)
    else
      authenticate_user!
    end
  end
end
