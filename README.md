# Introduction
 SimpleSSOProvider is built to solve the purpose of a fully-functional Single-sign-on system. SSO is implemented with devise, omniauth and jwt. Where devise is handling user management part including signin, signup, forgot and reset password etc. Omniauth is handling multi-provider authentication services for ex. facebook, google etc. and in our case a custom sso provider. And  JWT tokens will be used to secure our APIs across domains. 
 
 You can deploy this application in your system or server. For this document, I'm assuming that you've deployed the SSO provider at http://localhost:3000.

## Client Integration

To integrate your application with this Simple SSO Provider, follow the steps given below. 


* Add the following gems in your Gemfile and run bundle install.
```ruby
gem 'omniauth'
gem 'omniauth-oauth2'
gem "omniauth-rails_csrf_protection"
gem 'repost'
```

* Create a `sso.rb` file inside `lib` directory, with the following content:
```ruby
require 'omniauth-oauth2'
module OmniAuth
  module Strategies
    class Sso < OmniAuth::Strategies::OAuth2

      CUSTOM_PROVIDER_URL = 'http://localhost:3000' # Change this URL as per your provider URL

      option :client_options, {
        :site =>  CUSTOM_PROVIDER_URL,
        :authorize_url => "#{CUSTOM_PROVIDER_URL}/auth/sso/authorize",
        :access_token_url => "#{CUSTOM_PROVIDER_URL}/auth/sso/access_token"
      }

      uid do
        raw_info['id']
      end

      info do
        {
          :email => raw_info['info']['email']
        }
      end

      extra do
        {
          :first_name => raw_info['extra']['first_name'],
          :last_name  => raw_info['extra']['last_name']
        }
      end

      def raw_info
        @raw_info ||= access_token.get("/auth/sso/user.json?oauth_token=#{access_token.token}").parsed
      end
    end
  end
end
```

* Create `lib/json_web_token.rb` file with the following content:
```ruby
class JsonWebToken
  def self.encode(payload)
    JWT.encode(payload, Rails.application.secrets.jwt_key_base)
  end

  def self.decode(token)
    return HashWithIndifferentAccess.new(JWT.decode(token, Rails.application.secrets.jwt_key_base, true)[0])
  rescue
    nil
  end
end
```  
* In your terminal, run the following command to add `jwt_key_base` credential: `EDITOR="vim" bin/rails credentials:edit`
  
There you add the value for `jwt_key_base` and save it.
One important point to note is that, the access token coming from SSO provider is signed with a `jwt_key_base` on that end. So, in both SSO provider and client end, the `jwt_key_base` should be same.

* Create `config/initializers/extensions.rb` file with the following content:
```ruby
Dir["#{Rails.root}/lib/*.rb"].each {|file| require file }
```

* In your app environment set `config.eager_load = true`

* Create `users` table and migrate database

     rails g model User uid:string email:string status:string

* Now in your SSO Provider create a new OAuth Client. You will get a APP_ID and APP_SECRET there.

* Create `config/initiaizers/omniauth.rb` file with the following content: 
```ruby
# Change this omniauth configuration to point to your registered provider
# Since this is a registered application, add the app id and secret here
APP_ID = 'enter-your-app-id'
APP_SECRET = 'enter-your-app-secret'

CUSTOM_PROVIDER_URL = 'http://localhost:3000'

Rails.application.config.middleware.use OmniAuth::Builder do
  provider :sso, APP_ID, APP_SECRET
end
```
* Create a `app/controllers/oauth_callbacks_controller.rb` file with the following content:
```ruby
class OauthCallbacksController < ApplicationController
  before_action :authenticate_sso_user, only: [ :destroy ]

  # omniauth callback method
  #
  # First the callback operation is done
  # inside OmniAuth and then this route is called
  def create
    omniauth = env['omniauth.auth']
    logger.debug "+++ #{omniauth}"

    user = User.find_by_uid(omniauth['uid'])
    if not user
      # New user registration
      user = User.new(:uid => omniauth['uid'])
    end
    user.email = omniauth['info']['email']
    user.save

    #p omniauth

    # Currently storing all the info
    session[:user_id] = omniauth

    flash[:notice] = "Successfully logged in"
    redirect_to root_path
  end

  # Omniauth failure callback
  def failure
    flash[:notice] = params[:message]
  end

  # logout - Clear our rack session BUT essentially redirect to the provider
  # to clean up the Devise session from there too !
  def destroy
    session[:user_id] = nil

    flash[:notice] = 'You have successfully signed out!'
    redirect_to "#{CUSTOM_PROVIDER_URL}/users/sign_out"
  end
end
```
* Create two methods 'authenticate_sso_user' and 'current_user' in your application_controller.rb.
```ruby
  def authenticate_sso_user
    if !current_user
      respond_to do |format|
        format.html  {
          # redirect_to '/auth/sso' # Omniauth doesn't support GET request right now, so normal redirection will not work in this case and it will get a routing error. That's why repost gem is reuqired to redirect users using POST method.
          repost('auth/sso', options: {authenticity_token: :auto})
        }
        format.json {
          render :json => { 'error' => 'Access Denied' }.to_json
        }
      end
    end
  end

  def current_user
    case request.format
    when Mime[:json]
      return nil unless request.headers['Authorization']
      jwt_token = JsonWebToken.decode(request.headers['Authorization'])
      return nil unless jwt_token
      user = User.find_by_uid(jwt_token[:user_id])
      user = User.new(:uid => jwt_token[:user_id], email: jwt_token[:email]) if not user
      user.name = jwt_token[:name]
      user.save
      @current_user ||= user
    else
      return nil unless session[:user_id]
      @current_user ||= User.find_by_uid(session[:user_id]['uid'])
    end
  end
```
*  To protect any resource add `authenticate_sso_user` method as `before_action` in your controllers.

`before_action :authenticate_sso_user`

* Add the following routes in your `config/routes.rb`
```ruby
  # omniauth
  get '/auth/:provider/callback' => 'oauth_callbacks#create'
  get '/auth/failure' => 'oauth_callbacks#failure'

  # Custom logout
  match '/logout', :to => 'oauth_callbacks#destroy', via: :all
```
Thats it! Now restart your application and check in browser.

Note: Devise is not required in SSO client applications.


## API authentication

Follow the steps given below:

* Add the following gem in your Gemfile and run bundle install

    gem 'jwt'

* Copy lib/json_web_token.rb from repo to your project

* Add jwt secret key in config/secrets.yml for all app environments

    jwt_key_base: 89054jfokiut90ui90i8uig0j0990iy690i90iy69090gi90i097980ihjmkojteio5uiy906i09utijegiojkotlkj

Thats It! To make authenticated API calls send JWT token in `Authorization` header in every request.    
