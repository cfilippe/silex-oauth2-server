<?php
namespace OAuth2Server\Silex;
use OAuth2Server\Storage\SessionStore;
use OAuth2Server\Storage\ClientStore;
use OAuth2Server\Storage\ScopeStore;
use League\OAuth2\Server\Resource;
use League\OAuth2\Server\Authorization;
use League\OAuth2\Server\Grant\Password as PasswordGrantType;
use League\OAuth2\Server\Grant\AuthCode as AuthCodeGrantType;
use League\OAuth2\Server\Grant\ClientCredentials as ClientCredentialsGrantType;
use League\OAuth2\Server\Grant\RefreshToken as RefreshTokenGrantType;
use Silex\Application;
use Silex\ServiceProviderInterface;
class OAuth2ServiceProvider implements ServiceProviderInterface
{
    /**
     * {@inheritdoc}
     */
    public function register(Application $app)
    {
        $app['oauth2.session_manager'] = $app->share(function() use ($app) {
            return new SessionStore($app['db']);
        });
        $app['oauth2.client_manager'] = $app->share(function() use ($app) {
            return new ClientStore($app['db']);
        });
        $app['oauth2.scope_manager'] = $app->share(function() use ($app) {
            return new ScopeStore($app['db']);
        });
        $app['oauth2.resource_server'] = $app->share(function() use ($app) {
            return new Resource($app['oauth2.session_manager']);
        });
        $app['oauth2.auth_server'] = $app->share(function() use ($app) {
            $authServer = new Authorization($app['oauth2.client_manager'], $app['oauth2.session_manager'], $app['oauth2.scope_manager']);
            $options = isset($app['oauth2.options']) ? $app['oauth2.options'] : array();
            if (array_key_exists('access_token_ttl', $options)) {
                $authServer->setAccessTokenTTL($options['access_token_ttl']);
            }
            // Configure grant types.
            if (array_key_exists('grant_types', $options) && is_array($options['grant_types'])) {
                foreach ($app['oauth2.options']['grant_types'] as $type) {
                    switch ($type) {
                        case 'authorization_code':
                            $authServer->addGrantType(new AuthCodeGrantType());
                            break;
                        case 'client_credentials':
                            $authServer->addGrantType(new ClientCredentialsGrantType());
                            break;
                        case 'password':
                            if (!is_callable($options['password_verify_callback'])) {
                                throw new \RuntimeException('To use the OAuth2 "password" grant type, the "password_verify_callback" option must be set to a callback function.');
                            }
                            $grantType = new PasswordGrantType();
                            $grantType->setVerifyCredentialsCallback($options['password_verify_callback']);
                            $authServer->addGrantType($grantType);
                            break;
                        case 'refresh_token':
                            $authServer->addGrantType(new RefreshTokenGrantType());
                            break;
                        default:
                            throw new \RuntimeException('Invalid grant type "' . $type . '" specified in oauth2.options.');
                    }
                }
            }
            return $authServer;
        });
    }
    
    /**
     * {@inheritdoc}
     */
    public function boot(Application $app)
    {
    }
}
