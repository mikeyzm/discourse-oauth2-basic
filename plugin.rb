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

    current_info = ::PluginStore.get("oauth2_basic", "oauth2_basic_user_#{user_details[:user_id]}")
    if current_info
      result.user = User.where(id: current_info[:user_id]).first
      user = User.find_by(id: result.user.id)
      if user.custom_fields['sync_username'] != result.username
        sync_username(user, result.username)
      end
    elsif SiteSetting.oauth2_email_verified?
      result.user = User.where(email: Email.downcase(result.email)).first
      if result.user && user_details[:user_id]
        ::PluginStore.set("oauth2_basic", "oauth2_basic_user_#{user_details[:user_id]}", {user_id: result.user.id})
      end
    end

    result.extra_data = { oauth2_basic_user_id: user_details[:user_id], oauth2_basic_user_avatar: user_details[:avatar] }

    retrieve_avatar(result.user, user_details[:avatar])

    result
  end

  def sync_username(user, _username)
    if user.username != _username
      user.username = UserNameSuggester.suggest(_username)
      user.custom_fields['sync_username'] = _username
      user.save!
    end
  end

  def retrieve_avatar(user, image_url)
    return unless user
    return unless image_url
    return if user.user_avatar.try(:custom_upload_id).present?

    Jobs.enqueue(:download_avatar_from_url, url: image_url, user_id: user.id, override_gravatar: true)
  end

  def after_create_account(user, auth)
    ::PluginStore.set("oauth2_basic", "oauth2_basic_user_#{auth[:extra_data][:oauth2_basic_user_id]}", {user_id: user.id })
    sync_username(user,auth[:username])
    retrieve_avatar(user, auth[:extra_data][:oauth2_basic_user_avatar])
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
