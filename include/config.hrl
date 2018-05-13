
-define(SWAGGER_INFO_LINK, "https://esi.evetech.net/latest/swagger.json?datasource=tranquility").

-define(ESI_DATASOURCE,"tranquility").

-define(REDIRECT_URL, "").
-define(APPLICATION_ID, "").%% client id from https://developers.eveonline.com
-define(AUTH_TOKEN, "=="). %% precompiled  base64:encode(ClientID++":"++SecretKey)
-define(AUTH,"Basic "++?AUTH_TOKEN).
-define(SCOPE,"publicData%20esi-bookmarks.read_character_bookmarks.v1%20esi-location.read_location.v1"). %% define your scope here
