-module(basic_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

all() ->
  [
    init_test,

    %% public req tests
    req_2, %%  simple get request test
    req_3 %%  complex request without auth tokens test

    %% no test for character management and tokens request

  ].

init_per_suite(Config) ->
  application:stop(esi_box), %% stop app if it's already started
  Config.

init_per_testcase(_, Config) ->
  Config.

end_per_testcase(Case, Config) ->
  ct:print(info, "~p passed", [Case]),
  Config.

end_per_suite(Config) ->
  application:stop(esi_box), %% stop after tests
  Config.


init_test(_Config)->
  ?assertMatch({ok, _ }, application:ensure_all_started(esi_box)).

-define(N, 10).
req_2(_Config)->
  %% get list of categories avaliable
  Categories = esi_box:req("/universe/categories/", []),
  ?_assert( 0 =< length(Categories)),

  %% get N random categories
  CatListLength = length(Categories),
  SelectedCats=[lists:nth(rand:uniform(CatListLength), Categories)||_<- lists:duplicate(?N,0) ],

  [?assertMatch( #{<<"category_id">> := CatID,  <<"name">> := _CatName}, esi_box:req("/universe/categories/~p/", [CatID])) || CatID<-SelectedCats],
  ok.


req_3(_Config)->
    %% Get first page of public contracts in The Forge
    Page1 =  esi_box:req("/contracts/public/10000002/", []),
    %% Define page argument
    ?_assert(Page1 =:= esi_box:req(get, "/contracts/public/10000002/", [{"page", "1"}])),
    ?_assert(Page1 =/= esi_box:req(get, "/contracts/public/10000002/", [{"page", "5"}])),
    %% ask for non-existing page
    ?_assert([] =:= esi_box:req(get, "/contracts/public/10000002/", [{"page", "500"}])),
    %% get type info on another language (abadon)
    TypeID=24692,
    ?assertMatch(#{ <<"type_id">> := TypeID, <<"name">> := <<227,130,162,227,131,144,227,131,137,227,131,179>>}, esi_box:req(get, "/universe/types/~p/", {[TypeID],[{"language", "ja"}]})).
