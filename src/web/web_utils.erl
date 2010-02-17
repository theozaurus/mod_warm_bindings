%%%------------------------------------------------------------------------------
%%% File    : web_utils.erl
%%% Author  : Theo Cushion <theo@jivatechnology.com>
%%% Purpose : Provide helper functions for processing queries from HTTP requests
%%% Credit  : Builds on work by 'Tim'
%%%           http://github.com/tim/erlang-percent-encoding/blob/master/src/percent.erl
%%%           http://www.erlang.org/pipermail/erlang-questions/2009-January/041284.html
%%% Created : 02/02/2010
%%%------------------------------------------------------------------------------

-module(web_utils).
-author('theo@jivatechnology.com').

-export([
    uri_decode/1,
    param_decode/1
]).

-define(is_alphanum(C), C >= $A, C =< $Z; C >= $a, C =< $z; C >= $0, C =< $9).

%%
%% Param decoding.
%%

param_decode(Str) ->
    lists:map(fun([K,V]) ->
            % Turn 2D array into list of tuples
            % [["jid","foo@bar.com/hth"],["b","h"]] -> [{jid,"foo@bar.com/hth"},{b,"h"}]
            list_to_tuple([list_to_atom(K),V])
        end,
        param_split(Str)
    ).
param_split(Str) ->
    lists:map(
        % Split into array of parameters separated by &
        fun(E) ->
            lists:map(
                % Split each parameter section into key and value separated by =
                fun(A) ->
                    uri_decode(A)
                end,
                string:tokens(E,"=")
            )
        end,
        string:tokens(Str,"&")
    ).
%%
%% Percent decoding.
%%

uri_decode(Str) when is_list(Str) ->
    url_decode(Str, []).
url_decode([$%, A, B | T], Acc) ->
    Char = (hexchr_decode(A) bsl 4) + hexchr_decode(B),
    url_decode(T, [Char | Acc]);
url_decode([X | T], Acc) ->
    url_decode(T, [X | Acc]);
url_decode([], Acc) ->
    lists:reverse(Acc, []).


%%
%% Helper functions.
%%

-compile({inline, [{hexchr_decode, 1}]}).

hexchr_decode(C) when C >= $a ->
    C - $a + 10;
hexchr_decode(C) when C >= $A ->
    C - $A + 10;
hexchr_decode(C)->
    C - $0.
