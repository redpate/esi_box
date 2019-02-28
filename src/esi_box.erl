-module(esi_box).

-include("config.hrl").

-behaviour(gen_server).

%% api export

-export([start/0, start/1]).
-export([get_auth_url/1, auth/1, delete/1]).
-export([req/2, req/3, req/4, rreq/2, rreq/3, rreq/4, hreq/2, hreq/3, hreq/4]).

%% low level api export

-export([hcall/1, call/1, cast/1, start_link/1]).

%% server callbacks export

-export([init/1, handle_call/3, handle_call2/5]).

-export([handle_cast/2, handle_info/2, terminate/2, code_change/3]).


%% ESI token structure is simple and not worth creating record
%% ESI Record  - {CharacterID, IsValid, AccessToken, RefreshToken, CharacterName}

%% Interface

start()->
  start(?DEFAULT_CONFIG).
start(Config)->
  ?MODULE:start_link(Config).

get_auth_url(State)->
  ?MODULE:hcall({get_auth_url,State}).

auth(Code)->
  ?MODULE:hcall({auth,Code}).
delete(ID)->
  ?MODULE:hcall({del,ID}).

%% Blocking request with no headers returned (for compatibility with old projects)
req(Req, Body)->
  ?MODULE:call({req, Req, Body}).
req(Method, Req, Body)->
  ?MODULE:call({req, Method, Req, Body}).
req(Method, Req, Body, CharacterID)->
  ?MODULE:call({req, Method, Req, Body, CharacterID}).

%% Blocking request with headers returned

rreq(Req, Body)->
  ?MODULE:hcall({req, Req, Body}).
rreq(Method, Req, Body)->
  ?MODULE:hcall({req, Method, Req, Body}).
rreq(Method, Req, Body, CharacterID)->
    ?MODULE:hcall({req, Method, Req, Body, CharacterID}).

%% Nonblocking request with headers returned. Handle returned message by youself
hreq(Req, Body)->
  ?MODULE:cast({req, Req, Body}).
hreq(Method, Req, Body)->
  ?MODULE:cast({req, Method, Req, Body}).
hreq(Method, Req, Body, CharacterID)->
    ?MODULE:cast({req, Method, Req, Body, CharacterID}).

%% Gen_server part

start_link(Args) ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, Args, []). %% only one server, kinda bottleneck

init(#{db_file := DetsFileName, master_key:=_MasterKey, timeout := Timeout}=Args)->
  {ok, ?DETS_NAME} = dets:open_file(?DETS_NAME, [{access,read_write},{auto_save,60000},{file, DetsFileName}]),
  ETS = ets:new(sso_ets, [public]),
  error_logger:info_msg("~p opened as ~p DETS", [DetsFileName, ?DETS_NAME]),
  MasterKey = crypto:hash(sha512,_MasterKey),
  %% no check for valid MasterKey, for wrong one there gona be no valid esi tokens.
  {ok,maps:merge(get_swaggger_info(), Args#{master_key=>MasterKey, sso_ets => ETS})}.

cast(Req)-> %% nonblocking request (returned with headers)
  {ReceiveToken, Timeout}= gen_server:call(?MODULE, Req).

call(Req)-> %% blocking call to server, TODO cast variant
  {ReceiveToken, Timeout}= gen_server:call(?MODULE, Req),
  receive
    {esi_box, ReceiveToken, {_Header,Result}}->
      Result
  after
    Timeout ->
      timeout
  end.
hcall(Req)-> %% blocking call to server, TODO cast variant
  {ReceiveToken, Timeout}= gen_server:call(?MODULE, Req),
  receive
    {esi_box, ReceiveToken, Result}->
      Result
  after
    Timeout ->
      timeout
  end.

handle_call(A, From, #{timeout := Timeout}=State)->
  ReceiveToken = crypto:strong_rand_bytes(2),
  spawn(?MODULE,handle_call2, [A, From, ReceiveToken, self(), State]),
  {reply, {ReceiveToken, Timeout}, State}.

handle_call2(A, {FromPid,_Ref}=_From, ReceiveToken, ServerPid, State)->
  %%error_logger:error_msg("handle_call2~p",[[A, _From, ServerPid, State]]),
  Result = handle_call3(A,State),
  FromPid ! {esi_box, ReceiveToken, Result}.

handle_call3({get_auth_url, StateBin},#{sso_url := SSO_AUTH_ENDPOINT, sso_ets:= ETS, scope := Scope, application_id := ApplicationID, redirect_url:=RedirectUrl}=State)->
  generate_auth_url(StateBin, SSO_AUTH_ENDPOINT, Scope, ApplicationID, RedirectUrl);

handle_call3({auth, Code},#{sso_url := SSO_AUTH_ENDPOINT, sso_ets:= ETS, application_id := ClientId, master_key:=MasterKey, auth_token:=AuthToken}=State)->
  case catch token_auth(Code, SSO_AUTH_ENDPOINT, ClientId, AuthToken) of
    #{character_name:=CharacterName,
      character_id:=CharacterID,
      access_token:=AccessToken,
      expires_on:=ExpiresOn,
      refresh_token:=RefreshToken}->
        ok = dets:insert(?DETS_NAME, {CharacterID, true, encode(AccessToken, MasterKey), encode(RefreshToken, MasterKey), CharacterName, ExpiresOn}),
        {CharacterID, CharacterName};
    _Reason->
      error_logger:error_msg("Failed to verify ~p code (reason - ~p)", [Code, _Reason]),
        {error, Code , _Reason}
  end;

handle_call3({del, ID},State)->
  dets:delete(?DETS_NAME,ID);

handle_call3({req, Req, Body},#{sso_url := SSO_AUTH_ENDPOINT, esi_url := ESIUrl}=State)->
  request(Req, Body, ESIUrl);
handle_call3({req, Method, Req, Body},#{sso_url := SSO_AUTH_ENDPOINT, esi_url := ESIUrl, sso_ets:= ETS, master_key:=MasterKey, auth_token := Auth}=State)->
  request(Method, Req, Body, ESIUrl, "");
handle_call3({req, Method, Req, Body, CharacterID},#{sso_url := SSO_AUTH_ENDPOINT, esi_url := ESIUrl, sso_ets:= ETS, master_key:=MasterKey, auth_token := Auth,  application_id := ClientId}=State)->
  Res = dets:lookup(?DETS_NAME, CharacterID),
  case Res of
    [{CharacterID, IsValid, EncryptedAccessToken, EncryptedRefreshToken, CharacterName, ExpiresOn}]->
      IsExpired = os:system_time(second) >= ExpiresOn,
      AccessToken = if
        IsExpired ->
          %%error_logger:info_msg("~p/~p Token expired, refreshing...", [CharacterID, CharacterName]),
          #{access_token := NewAccessToken,
           expires_on := NewExpiresOn,
           refresh_token := NewRefreshToken}  = update_token(decode(EncryptedRefreshToken, MasterKey), SSO_AUTH_ENDPOINT, Auth, ClientId),
          ok = dets:insert(?DETS_NAME, {CharacterID, true, encode(NewAccessToken, MasterKey), encode(NewRefreshToken, MasterKey), CharacterName, NewExpiresOn}),
          %%error_logger:info_msg("~p/~p Token updated...", [CharacterID, CharacterName]),
          NewAccessToken;
        true->
          decode(EncryptedAccessToken, MasterKey)
      end,
      request(Method, Req, Body, ESIUrl, AccessToken);
    _Reason ->
      error_logger:error_msg("Failed to make request with ~p token (reason - ~p)", [CharacterID, _Reason]),
      {error, CharacterID , _Reason}
  end;

handle_call3(get,_State)->
  _State;
handle_call3(_,_State)->
  unknown.

handle_cast(_Request, State) ->
  {noreply, State}.

handle_info(Info, State) ->
  {noreply, State}.

terminate(_Reason, _State) ->
  dets:close(?DETS_NAME),
  ok.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.



%% internal functions

get_swaggger_info()->
{ok,{{_,200,_}, _Headers, Body}} = httpc:request(?SWAGGER_INFO_LINK),
 #{
    <<"parameters">> := ParametersMap,
    <<"info">> := #{<<"version">> := Version},
    <<"basePath">> := BasePath,
    <<"definitions">> :=DefinitionsMap,
    <<"host">> := EsiHost,
    <<"schemes">> := Schemes,
    <<"securityDefinitions">> := SsoMap
  } = jiffy:decode(Body, [return_maps]),
#{<<"evesso">> := #{<<"authorizationUrl">> := AuthorizationUrl, <<"scopes">> := ScopeMap}} = SsoMap,
error_logger:info_msg("Loaded esi swagger spec (v~s)", [Version]),
Sheme = hd(Schemes),
#{sso_url => binary_to_list(AuthorizationUrl),
  %scopes => ScopeMap, %% have statis scope, noneed to  not using
  esi_url => << Sheme/binary, "://", EsiHost/binary, BasePath/binary >>,
  version => Version
}.

token_auth(Code, SSO_AUTH_ENDPOINT, ClientId, AuthToken)->
  error_logger:info_msg("{Code, SSO_AUTH_ENDPOINT, ClientId, AuthToken}=~p", [{Code, SSO_AUTH_ENDPOINT, ClientId, AuthToken}]),
  {ok,{{_,200,_}, _Headers, Body}} = httpc:request(post,
      {SSO_AUTH_ENDPOINT++"/../token", [{"Authorization" ,
           lists:flatten(io_lib:format("~s ~s", ["Basic", AuthToken]))
      }, {"User-Agent", "FRACKING"}],
      "application/json",
      jiffy:encode(#{ grant_type => <<"authorization_code">>, code => Code, client => list_to_binary(ClientId)})
      }, [], []),
  #{
    <<"access_token">> := AccessToken,
    <<"token_type">> := TokenType,
    <<"expires_in">> := ExpiresIn,
    <<"refresh_token">> := RefreshToken
  } = jiffy:decode(list_to_binary(Body), [return_maps]),
  RequestTokenResponse= obtain_character_id(AccessToken),
  RequestTokenResponse#{
    token_type => TokenType,
    access_token => AccessToken,
    expires_on =>  ExpiresIn+os:system_time(second),
    refresh_token => RefreshToken,
    id => crypto:hash(sha256, Code)}.

obtain_character_id(AccessToken)->
  [_Header, Body, _Sig]=A=binary:split(AccessToken, <<$.>>, [global]),
   #{<<"name">> := CharacterName,
     <<"exp">> := Expires,
     <<"scp">> := Scope,
     <<"sub">> := _CharacterID
    }= jiffy:decode(base64:decode(restore_base64(Body)), [return_maps]), %% no signature verifing, if someone messed up https session we are already fucked
    <<"CHARACTER:EVE:", CharacterID/binary>> = _CharacterID,
    #{
      character_name => CharacterName,
      character_id => CharacterID,
      expires_in => Expires,
      scope => Scope
    }.

restore_base64(Body)->
  case (size(Body) rem 4) of
    0->
      Body;
    N->
      Filler = binary:copy(<<"=">>, 4-N),
      <<Body/binary, Filler/binary>>
  end.


update_token(RefreshToken, SSO_AUTH_ENDPOINT, Auth,  ClientId)->
  {ok,{{_,200,_}, _Headers, Body}} = httpc:request(post,
                    {SSO_AUTH_ENDPOINT++"/../token", [{"Authorization" ,
                         lists:flatten(io_lib:format("~s ~s", ["Basic", Auth]))
                    }, {"User-Agent", "teki"}],
                    "application/json",
                    jiffy:encode(#{ grant_type => <<"refresh_token">>, refresh_token => RefreshToken, client => list_to_binary(ClientId)})
                    }, [], []),
  #{
    <<"access_token">> := AccessToken,
    <<"token_type">> := TokenType,
    <<"expires_in">> := ExpiresIn,
    <<"refresh_token">> := RefreshToken
  } = jiffy:decode(list_to_binary(Body), [return_maps]),
  RequestTokenResponse= obtain_character_id(AccessToken),
  RequestTokenResponse#{
    token_type => TokenType,
    access_token => AccessToken,
    expires_on => ExpiresIn+os:system_time(second),
    refresh_token => RefreshToken}.

generate_auth_url(State, SSO_AUTH_ENDPOINT, Scope, ApplicationID, RedirectUrl)->
  lists:flatten(io_lib:format("~s/?response_type=code&redirect_uri=~s&client_id=~s&scope=~s&state=~s", [SSO_AUTH_ENDPOINT, RedirectUrl, ApplicationID, Scope, State])).

compile_request(ReqFormat, Data)->
  lists:flatten(io_lib:format(ReqFormat, Data)).

request(ReqFormat, Data, ESIUrl)->
  {ok,{_, _,Body}}=httpc:request(get,
                    {lists:flatten(io_lib:format("~s~s?datasource=~s", [ESIUrl,compile_request(ReqFormat, Data), ?ESI_DATASOURCE])), []}, [], []),
  decode(Body).
request(get, Req, ESIUrl,  SSO)->
  request(get, Req, {<<>>, []}, ESIUrl, SSO).
request(get, Req, ReqBody, ESIUrl, AccessToken) when is_list(ReqBody)->
  request(get, Req, {[], ReqBody}, ESIUrl, AccessToken);
request(get, ReqFormat, {UriData, ReqBody}, ESIUrl, AccessToken)->
  BodyReq=lists:flatten(lists:foldr(fun({X,Y},Acc)-> ["&"++X++"="++Y|Acc]  end,[],ReqBody)),
  {ok,{_, Header,Body}}=httpc:request(get,
                    {lists:flatten(io_lib:format("~s~s?datasource=~s~s", [ESIUrl, compile_request(ReqFormat, UriData), ?ESI_DATASOURCE, BodyReq])),
                    [{"Authorization" ,
                         lists:flatten(io_lib:format("~s ~s", ["Bearer", AccessToken]))
                    }, {"User-Agent", "teki"}]
                    }, [], []),
  {Header,decode(Body)};
request(Method, Req, ReqBody, ESIUrl, AccessToken) when is_list(ReqBody)->
  BodyReq=lists:flatten(lists:foldr(fun({X,Y},Acc)-> ["&"++X++"="++Y|Acc]  end,[],ReqBody)),
{ok,{_, Header,Body}}=httpc:request(Method,
                    {lists:flatten(io_lib:format("~s~s?datasource=~s~s", [ESIUrl, Req, ?ESI_DATASOURCE,BodyReq])), [{"Authorization" ,
                         lists:flatten(io_lib:format("~s ~s", ["Bearer", AccessToken]))
                    }, {"User-Agent", "teki"}],
                    "application/json",
                    []
                    }, [], []),
  {Header,decode(Body)};
request(Method, Req, ReqBody, ESIUrl, AccessToken) when is_binary(ReqBody)->
  {ok,{_, Header,Body}}=httpc:request(Method,
                    {lists:flatten(io_lib:format("~s~s?datasource=~s", [ESIUrl, Req, ?ESI_DATASOURCE])), [{"Authorization" ,
                         lists:flatten(io_lib:format("~s ~s", ["Bearer", AccessToken]))
                    }, {"User-Agent", "teki"}],
                    "application/json",
                    ReqBody
                    }, [], []),
  {Header,decode(Body)};
request(Method, Req, ReqBody, ESIUrl, AccessToken)->
  {ok,{_, Header,Body}}=httpc:request(Method,
                    {lists:flatten(io_lib:format("~s~s?datasource=~s", [ESIUrl, Req, ?ESI_DATASOURCE])), [{"Authorization" ,
                         lists:flatten(io_lib:format("~s ~s", ["Bearer", AccessToken]))
                    }, {"User-Agent", "teki"}],
                    "application/x-www-form-urlencoded",
                    ReqBody
                    }, [], []),
  {Header,decode(Body)}.

decode([])->#{};
decode(A)->jiffy:decode(A, [return_maps]).


%% simple crypto
encode(Data, Key1)->
  PubKey = crypto:strong_rand_bytes(9),
  FillerSize = 16-(byte_size(Data) rem 16),
  B2 = binary:copy(<<0>>, FillerSize),
  PrivKey = crypto:hash(sha256, <<Key1/binary,  PubKey/binary>>),
  {crypto:block_encrypt(aes_ecb, PrivKey, <<Data/binary, B2/binary>>), <<FillerSize, PubKey/binary>>}.

decode({Data,  <<FillerSize, PubKey/binary>>}, Key1)->
  PrivKey = crypto:hash(sha256, << Key1/binary, PubKey/binary>>),
  DecryptedBlocks = crypto:block_decrypt(aes_ecb, PrivKey, Data),
  binary:part(DecryptedBlocks, {0, byte_size(DecryptedBlocks)-FillerSize}).
