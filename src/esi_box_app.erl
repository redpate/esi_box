%%%-------------------------------------------------------------------
%% @doc esi_box public API
%% @end
%%%-------------------------------------------------------------------

-module(esi_box_app).

-behaviour(application).

-include("config.hrl").

%% Application callbacks
-export([start/0, start/2, stop/1]).

%%====================================================================
%% API
%%====================================================================

start() ->
  Config = application:get_env(esi_box, config ,?DEFAULT_CONFIG),
  esi_box:start(Config).
start(_StartType, _StartArgs) ->
    esi_box_sup:start_link().

%%--------------------------------------------------------------------
stop(_State) ->
    ok.

%%====================================================================
%% Internal functions
%%====================================================================
