# name: discourse-oauth2-basic
# about: Generic OAuth2 Plugin
# version: 0.2
# authors: Robin Ward

require_dependency 'auth/oauth2_authenticator.rb'

enabled_site_setting :oauth2_enabled

class ::OmniAuth::Strategies::Oauth2Basic < ::OmniAuth::Strategies::OAuth2
  option :name, "oauth2_basic"
  info do
    {
      id: access_token['id']
    }
  end

  def callback_url
    full_host + script_name + callback_path
  end
end

class OAuth2BasicAuthenticator < ::Auth::OAuth2Authenticator
  def register_middleware(omniauth)
    omniauth.provider :oauth2_basic,
                      name: 'oauth2_basic',
                      setup: lambda {|env|
                        opts = env['omniauth.strategy'].options
                        opts[:client_id] = SiteSetting.oauth2_client_id
                        opts[:client_secret] = SiteSetting.oauth2_client_secret
                        opts[:provider_ignores_state] = true
                        opts[:client_options] = {
                          authorize_url: SiteSetting.oauth2_authorize_url,
                          token_url: SiteSetting.oauth2_token_url
                        }
                        opts[:authorize_options] = SiteSetting.oauth2_authorize_options.split("|").map(&:to_sym)

                        if SiteSetting.oauth2_send_auth_header?
                          opts[:token_params] = {headers: {'Authorization' => basic_auth_header }}
                        end
                      }
  end

  def basic_auth_header
    "Basic " + Base64.strict_encode64("#{SiteSetting.oauth2_client_id}:#{SiteSetting.oauth2_client_secret}")
  end

  def walk_path(fragment, segments)
    first_seg = segments[0]
    return if first_seg.blank? || fragment.blank?
    return nil unless fragment.is_a?(Hash)
    deref = fragment[first_seg] || fragment[first_seg.to_sym]

    return (deref.blank? || segments.size == 1) ? deref : walk_path(deref, segments[1..-1])
  end

  def json_walk(result, user_json, prop)
    path = SiteSetting.send("oauth2_json_#{prop}_path")
    if path.present?
      segments = path.split('.')
      val = walk_path(user_json, segments)
      result[prop] = val if val.present?
    end
  end

  def log(info)
    Rails.logger.warn("OAuth2 Debugging: #{info}") if SiteSetting.oauth2_debug_auth
  end

  def fetch_user_details(token, id)
    user_json_url = SiteSetting.oauth2_user_json_url.sub(':token', token.to_s).sub(':id', id.to_s)

    log("user_json_url: #{user_json_url}")

    user_json = JSON.parse(open(user_json_url, 'Authorization' => "Bearer #{token}" ).read)

    log("user_json: #{user_json}")

    result = {}
    if user_json.present?
      json_walk(result, user_json, :user_id)
      json_walk(result, user_json, :username)
      json_walk(result, user_json, :name)
      json_walk(result, user_json, :email)
      json_walk(result, user_json, :avatar)
    end

    result
  end

  def after_authenticate(auth)
    log("after_authenticate response: \n\ncreds: #{auth['credentials'].to_hash}\ninfo: #{auth['info'].to_hash}\nextra: #{auth['extra'].to_hash}")

    result = Auth::Result.new
    token = auth['credentials']['token']
    user_details = fetch_user_details(token, auth['info'][:id])

    result.name = user_details[:name]
    result.username = user_details[:username]
    result.email = user_details[:email]
    result.email_valid = result.email.present? && SiteSetting.oauth2_email_verified?

    if User.find_by_email(result.email).nil?
      user = User.create(email: result.email, username: result.username, active: result.email_valid)
    end

    user = User.find_by_email(result.email)

    if sso_record = user.single_sign_on_record
      if sso_record.external_username != result.username
        update_username(user, result.username)
        sso_record.external_username = result.username
      end
      sso_record.avatar_url = user_details[:avatar]
      sso_record.save!
    else
      user.create_single_sign_on_record(
          last_payload: '',
          external_id: user_details[:user_id],
          external_username: user_details[:username],
          external_email: user_details[:email],
          external_avatar_url: user_details[:avatar]
      )
    end

    retrieve_avatar(user, user_details[:avatar])
    result.user = user

    result
  end

  def update_username(user, _username)
      user.username = UserNameSuggester.suggest(_username)
      user.save!
  end

  def retrieve_avatar(user, image_url)
    return unless user
    return unless image_url
    return if user.user_avatar.try(:custom_upload_id).present?

    Jobs.enqueue(:download_avatar_from_url, url: image_url, user_id: user.id, override_gravatar: true)
  end

  def after_create_account(user, auth)
    sync_username(user,auth[:username])
  end
end

auth_provider title_setting: "oauth2_button_title",
              enabled_setting: "oauth2_enabled",
              authenticator: OAuth2BasicAuthenticator.new('oauth2_basic'),
              message: "正在使用神社账号登录..."

register_css <<CSS

  button.btn-social.oauth2_basic {
    background-color: #eb6363;
  }

CSS
