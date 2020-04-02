# frozen_string_literal: true

# name: neon-crm
# about: NeonCRM OAuth2 Plugin
# version: 0.1.0
# authors: Muhlis Cahyono (muhlisbc@gmail.com)
# url: https://github.com/muhlisbc/discourse-neon-crm

enabled_site_setting :neon_enabled

class ::OmniAuth::Strategies::Neon < ::OmniAuth::Strategies::OAuth2
  option :name, 'neon'

  uid do
    access_token.token
  end

  info do
    {}
  end

  def callback_url
    Discourse.base_url_no_prefix.sub('localhost', '127.0.0.1') + script_name + callback_path
  end
end

class NeonAuthenticator < Auth::ManagedAuthenticator
  def name
    'neon'
  end

  def can_revoke?
    SiteSetting.neon_allow_association_change
  end

  def can_connect_existing_user?
    SiteSetting.neon_allow_association_change
  end

  def neon_authorize_url
    "https://#{SiteSetting.neon_org_id}.z2systems.com/np/oauth/auth"
  end

  def neon_token_url
    if trial_mode?
      return 'https://trial.z2systems.com/np/oauth/token'
    end

    'https://wwww.z2systems.com/np/oauth/token'
  end

  def avatar_url(user_id)
    host = trial_mode? ? "trial.z2systems.com" : SiteSetting.neon_hostname

    "https://#{host}/neon/resource/efaosandbox/images/account/#{user_id}/0_large.jpg"
  end

  def register_middleware(omniauth)
    omniauth.provider :neon,
                      name: name,
                      setup: lambda { |env|
                        opts = env['omniauth.strategy'].options
                        opts[:client_id] = SiteSetting.neon_client_id
                        opts[:client_secret] = SiteSetting.neon_client_secret
                        opts[:provider_ignores_state] = false
                        opts[:client_options] = {
                          authorize_url: neon_authorize_url,
                          token_url: neon_token_url,
                          token_method: :post
                        }
                      }
  end

  def log(info)
    if SiteSetting.neon_debug_enabled
      Rails.logger.warn("Neon Debugging: #{info}")
    end
  end

  def neon_endpoint
    host = trial_mode? ? 'trial.z2systems.com' : 'api.neoncrm.com'

    "https://#{host}/neonws/"
  end

  def trial_mode?
    SiteSetting.neon_trial_mode
  end

  def neon_session_id
    PluginStore.get('neon', 'session_id') || neon_get_session_id
  end

  def neon_get_session_id
    url = neon_endpoint + 'services/api/common/login'
    query = {
      'login.apiKey' => SiteSetting.neon_api_key,
      'login.orgid' => SiteSetting.neon_org_id
    }

    log2 = ->(s) { log("get session ID - #{s}") }

    attempts = 0
    session_id = nil

    loop do
      attempts += 1

      begin
        log2.call(url)
        log2.call(query.as_json)

        body = Excon.get(url, query: query).body
        resp = JSON.parse(body)['loginResponse']
        status = resp['operationResult']

        if status == 'SUCCESS'
          session_id = resp['userSessionId']
        else
          errors = resp['errors']
          log2.call("error: #{errors}")
        end
      rescue => e
        log2.call("request error: #{e}")
      end

      if session_id.present? || attempts >= 3
        break
      end
    end

    if session_id.blank?
      log2.call('failed after 3 attempts')
    else
      log2.call(session_id)
      PluginStore.set('neon', 'session_id', session_id)
    end

    session_id
  end

  def fetch_user_details(id)
    session_id = neon_session_id

    return if session_id.blank?

    log2 = ->(s) { log("fetch user #{id} - #{s}") }
    url = neon_endpoint + 'services/api/account/retrieveIndividualAccount'

    attempts = 0
    result = nil

    loop do
      attempts += 1

      begin
        query = {
          userSessionId: session_id,
          accountId: id
        }

        log2.call(url)
        log2.call(query.as_json)

        body = Excon.get(url, query: query).body
        resp = JSON.parse(body)['retrieveIndividualAccountResponse']
        status = resp['operationResult']

        if status == 'SUCCESS'
          resp = resp['individualAccount']

          name = [
            resp.dig('primaryContact', 'firstName'),
            resp.dig('primaryContact', 'lastName')
          ].compact.join(' ').strip

          result = {
            nickname: resp.dig('login', 'username'),
            email: resp.dig('primaryContact', 'email1'),
            name: name,
            image: avatar_url(id)
          }
        else
          errors = resp['errors']
          log2.call("error: #{errors}")

          # expired
          if errors['error'].map { |e| e['errorCode'].to_i }.include?(4)
            session_id = neon_get_session_id
          end

          raise StandardError.new(errors)
        end
      rescue => e
        log2.call("request error: #{e}")
      end

      if result.present? || attempts >= 3
        break
      end
    end

    if result.blank?
      log2.call('failed after 3 attempts')
    end

    result
  end

  def primary_email_verified?(_auth)
    SiteSetting.neon_email_verified
  end

  def always_update_user_email?
    SiteSetting.neon_overrides_email
  end

  def after_authenticate(auth, existing_account: nil)
    log("after_authenticate response: \n\ncreds: #{auth['credentials'].to_hash}\nuid: #{auth['uid']}\ninfo: #{auth['info'].to_hash}\nextra: #{auth['extra'].to_hash}")


    user_details = fetch_user_details(auth['uid'])

    if user_details.present?
      %w[nickname name email image].each do |property|
        auth['info'][property] = user_details[property.to_sym] if user_details[property.to_sym]
      end
    else
      result = Auth::Result.new
      result.failed = true
      result.failed_reason = I18n.t('neon.authenticator_error_fetch_user_details')
      return result
    end

    super(auth, existing_account: existing_account)
  end

  def enabled?
    SiteSetting.neon_enabled
  end
end

auth_provider title_setting: 'neon_button_title',
              authenticator: NeonAuthenticator.new,
              message: 'NeonCRM'

register_css <<CSS

  button.btn-social.neon {
    background-color: #6d6d6d;
  }

CSS
