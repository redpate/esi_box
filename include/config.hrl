
-define(SWAGGER_INFO_LINK, "https://esi.evetech.net/latest/swagger.json?datasource=tranquility").

-define(ESI_DATASOURCE,"tranquility").


-define(DETS_NAME, esi_bb). %% probaly should include this in config

-define(REDIRECT_URL, "").
-define(APPLICATION_ID, "").%% client id from https://developers.eveonline.com
-define(AUTH_TOKEN, "=="). %% precompiled  base64:encode(ClientID++":"++SecretKey)
-define(AUTH,"Basic "++?AUTH_TOKEN).
-define(SCOPE,"publicData"). %% define your scope here

-define(DEFAULT_CONFIG, #{db_file=>"test.db", master_key=> <<"somelongkey">>, timeout => 10000, application_id => ?APPLICATION_ID, auth_token => ?AUTH, scope => ?SCOPE}).
