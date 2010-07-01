%%%------------------------------------------------------------------------
%%% File    : mod_warm_bindings.erl
%%% Author  : Theo Cushion <theo@jivatechnology.com>
%%% Purpose : Enables the creation of authenticated BOSH sessions via HTTP
%%% Created : 29/01/2010
%%%------------------------------------------------------------------------

-module(mod_warm_bindings).
-author('theo@jivatechnology.com').

-behaviour(gen_mod).

-export([
    start/2,
    stop/1,
    process/2
    ]).
    
-import(web_utils,[param_decode/1]).

-include("ejabberd.hrl").
-include("jlib.hrl").
-include("ejabberd_http.hrl").

-define(LANG, "en").
-define(WAIT, "60").
-define(HOLD, "1").
-define(VER,  "1.6").

-record(binding, {jid, sid, rid}).

%%%----------------------------------------------------------------------
%%% REQUEST HANDLERS
%%%----------------------------------------------------------------------

process([], #request{auth = Auth, ip = IP, method = 'POST', data = Data}) ->
    try warm(Auth,IP,Data)
    catch
        T:X -> ?ERROR_MSG("Exception while warming binding~n"
                          "** Tag: ~p~n"
                          "** Error: ~p~n"
                          "** Stacktrace: ~p~n",
                          [T,X,erlang:get_stacktrace()])
    end;
process([], #request{auth = Auth, method = 'GET', path = FullPath}) ->
    case auth_admin(Auth) of
        success      -> form(FullPath);
        forbidden    -> forbidden();
        unauthorized -> unauthorized()
    end;
process(Path, Request) -> 
    ?DEBUG("Bad Request ~p to ~p", [Request, Path]),
    badrequest().

%%%----------------------------------------------------------------------
%%% LOGIN HELPERS
%%%----------------------------------------------------------------------

warm(Auth,IP,Data) ->
    case auth_admin(Auth) of
        success -> 
            ?INFO_MSG("Params ~p",[Data]),
            DecodedData = param_decode(Data),
            {value,{_,SJID}} = lists:keysearch(jid,      1, DecodedData),
            {value,{_,Pass}} = lists:keysearch(password, 1, DecodedData),
            case is_list(SJID) andalso is_list(Pass) of
                true  ->
                    case bind(SJID, Pass, IP, DecodedData) of
                        false   -> badrequest();
                        Binding -> success(Binding)
                    end;
                false -> badrequest()
            end;
        forbidden    -> forbidden();
        unauthorized -> unauthorized()
    end.

%%% Checks that a user is an admin
auth_admin(Auth) ->
    case Auth of
        {SJID, P} ->
            % Check jid is valid
            case jlib:string_to_jid(SJID) of
                JID = #jid{user = U, server = S} ->
                    % Check password is correct
                    case ejabberd_auth:check_password(U, S, P) of
                        true -> 
                            % Check user is an admin
                            case acl:match_acl(admin,JID,S) of
                                true  -> 
                                    ?INFO_MSG("Authorized ~p",[U]),
                                    success;
                                false -> 
                                    ?INFO_MSG("Forbidden ~p",[U]),
                                    forbidden
                            end;
                        false ->
                            ?INFO_MSG("Unauthorized ~p",[U]),
                            unauthorized
                    end;
                error ->
                    ?INFO_MSG("Unauthorized ~p",[SJID]),
                    unauthorized
            end;
        _ ->
            ?INFO_MSG("Unauthorized",[]),
            unauthorized
    end.
    
bind(SJID, Password, IP, Data) ->
    #jid{user = User, server = Server, resource = Resource} = jlib:string_to_jid(SJID),
    
    Lang        = default_value( lang, Data, ?LANG ),
    Wait        = default_value( wait, Data, ?WAIT ),
    Hold        = default_value( hold, Data, ?HOLD ),
    Ver         = default_value( ver,  Data, ?VER  ),
    
    RidSessionCreate  = list_to_integer(randoms:get_string()),
    RidAuth           = RidSessionCreate  + 1,
    RidSessionRestart = RidAuth           + 1,
    RidResourceBind   = RidSessionRestart + 1,
    RidSessionRequest = RidResourceBind   + 1,
    RidNext           = RidSessionRequest + 1,
    
    {xmlelement, "body", Attrs1, _ } = process_request("<body rid='"++integer_to_list(RidSessionCreate)++"' xmlns='http://jabber.org/protocol/httpbind' to='"++Server++"' xml:lang='"++Lang++"' wait='"++Wait++"' hold='"++Hold++"' ver='"++Ver++"' content='text/xml; charset=utf-8' xmpp:version='1.0' xmlns:xmpp='urn:xmpp:xbosh'/>", IP),
    {value, {_, Sid}}    = lists:keysearch("sid",    1, Attrs1),
    {value, {_, AuthID}} = lists:keysearch("authid", 1, Attrs1),
    Auth = base64:encode_to_string(AuthID++[0]++User++[0]++Password),
    case process_request("<body rid='"++integer_to_list(RidAuth)++"' xmlns='http://jabber.org/protocol/httpbind' sid='"++Sid++"'><auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>"++Auth++"</auth></body>", IP) of
        {xmlelement,"body",_,[{xmlelement,"success",_,_}]} ->
            process_request("<body rid='"++integer_to_list(RidSessionRestart)++"' xmlns='http://jabber.org/protocol/httpbind' sid='"++Sid++"' to='"++Server++"' xml:lang='en' xmpp:restart='true' xmlns:xmpp='urn:xmpp:xbosh'/>", IP),
            case Resource of
                [] -> 
                    {_,_,_,[{_,_,_,[{_,_,_,[{_,_,_,[{_,JID}]}]}]}]} = process_request("<body rid='"++integer_to_list(RidResourceBind)++"' xmlns='http://jabber.org/protocol/httpbind' sid='"++Sid++"'><iq type='set'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></iq></body>", IP);
                _  -> 
                    {_,_,_,[{_,_,_,[{_,_,_,[{_,_,_,[{_,JID}]}]}]}]} = process_request("<body rid='"++integer_to_list(RidResourceBind)++"' xmlns='http://jabber.org/protocol/httpbind' sid='"++Sid++"'><iq type='set'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>"++Resource++"</resource></bind></iq></body>", IP)
            end,
            process_request("<body rid='"++integer_to_list(RidSessionRequest)++"' xmlns='http://jabber.org/protocol/httpbind' sid='"++Sid++"'><iq type='set'><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></iq></body>", IP),
            #binding{jid = binary_to_list(JID), sid = Sid, rid = integer_to_list(RidNext)};   
        _ ->
            ?DEBUG("User binding credentials wrong", []),
            false
    end.
    
default_value(Name, Data, Default) ->
    case lists:keysearch(Name, 1, Data) of
        {value, {_, Possible}} ->
            case is_list(Possible) of
                true -> Possible;
                _    -> Default
            end;
        _ ->
            Default
    end.
    
process_request(Request, IP) ->
    {_, _, Response} = ejabberd_http_bind:process_request(Request, IP),
    xml_stream:parse_element(lists:flatten(Response)).
    
%%%----------------------------------------------------------------------
%%% VIEWS
%%%----------------------------------------------------------------------
form(Path) ->
    {200,[],
        {xmlelement, "html", [{"xmlns", "http://www.w3.org/1999/xhtml"}, {"xml:lang", "en"}],[
            {xmlelement, "head", [], [
                {xmlelement, "title", [], [
                    {xmlcdata, "Warm Binding"}
                ]}
            ]},
            {xmlelement, "body", [], [
                {xmlelement, "form", [{"action","/"++filename:join(Path)},{"method","post"}], [
                    {xmlelement, "fieldset",[],[
                        {xmlelement, "legend",[],[{xmlcdata, "Credentials"}]},
                        {xmlelement, "ol",[],[
                            {xmlelement, "li",[],[
                                {xmlelement, "label", [{"for","jid"}], [{xmlcdata, "JID"}]},
                                {xmlelement, "input", [{"type","text"},{"name","jid"}], []}
                            ]},
                            {xmlelement, "li",[],[
                                {xmlelement, "label", [{"for", "password"}], [{xmlcdata, "Password"}]},
                                {xmlelement, "input", [{"type","password"},{"name","password"}], []}
                            ]}
                        ]}
                    ]},
                    {xmlelement, "fieldset",[],[
                        {xmlelement, "legend",[],[{xmlcdata, "Connection Options"}]},
                        {xmlelement, "ol",[],[
                            {xmlelement, "li",[],[
                                {xmlelement, "label", [{"for","lang"}], [{xmlcdata, "Language"}]},
                                {xmlelement, "input", [{"type","text"},{"name","lang"},{"value",?LANG}], []}
                            ]},
                            {xmlelement, "li",[],[
                                {xmlelement, "label", [{"for","wait"}], [{xmlcdata, "Wait"}]},
                                {xmlelement, "input", [{"type","text"},{"name","wait"},{"value",?WAIT}], []}
                            ]},
                            {xmlelement, "li",[],[
                                {xmlelement, "label", [{"for","hold"}], [{xmlcdata, "Hold"}]},
                                {xmlelement, "input", [{"type","text"},{"name","hold"},{"value",?HOLD}], []}
                            ]},
                            {xmlelement, "li",[],[
                                {xmlelement, "label", [{"for","ver"}], [{xmlcdata, "BOSH Version"}]},
                                {xmlelement, "input", [{"type","text"},{"name","ver"},{"value",?VER}], []}
                            ]}
                        ]}
                    ]},
                    {xmlelement, "input", [{"type","submit"},{"value","Bind"}], []}
                ]}
            ]}
        ]}
    }.
    
success(Binding) ->
    {200,[],
        {xmlelement, "html", [{"xmlns", "http://www.w3.org/1999/xhtml"}, {"xml:lang", "en"}],[
            {xmlelement, "head", [], [
                {xmlelement, "title", [], [
                    {xmlcdata, "Success"}
                ]}
            ]},
            {xmlelement, "body", [], [
                {xmlelement, "p", [], [
                    {xmlcdata, "Success"}
                ]},
                {xmlelement, "dl", [{"class","binding"}], [
                    {xmlelement, "dt", [{"class","jid"}], [{xmlcdata, "JID"}]},
                    {xmlelement, "dd", [{"class","jid"}], [{xmlcdata, Binding#binding.jid}]},
                    {xmlelement, "dt", [{"class","sid"}], [{xmlcdata, "SID"}]},
                    {xmlelement, "dd", [{"class","sid"}], [{xmlcdata, Binding#binding.sid}]},
                    {xmlelement, "dt", [{"class","rid"}], [{xmlcdata, "RID"}]},
                    {xmlelement, "dd", [{"class","rid"}], [{xmlcdata, Binding#binding.rid}]}
                ]}
            ]}
        ]}
    }.

forbidden() ->
    {403,[],
        {xmlelement, "html", [{"xmlns", "http://www.w3.org/1999/xhtml"}, {"xml:lang", "en"}],[
            {xmlelement, "head", [], [
                {xmlelement, "title", [], [
                    {xmlcdata, "Forbidden"}
                ]}
            ]},
            {xmlelement, "body", [], [
                {xmlelement, "p", [], [
                    {xmlcdata, "Forbidden"}
                ]}
            ]}
        ]}
    }.
    
unauthorized() ->
    {401,[{"WWW-Authenticate", "basic realm='HTTP Binding Warm'"}],
        {xmlelement, "html", [{"xmlns", "http://www.w3.org/1999/xhtml"}, {"xml:lang", "en"}],[
            {xmlelement, "head", [], [
                {xmlelement, "title", [], [
                    {xmlcdata, "Unauthorized"}
                ]}
            ]},
            {xmlelement, "body", [], [
                {xmlelement, "p", [], [
                    {xmlcdata, "Unauthorized"}
                ]}
            ]}
        ]}
    }.

badrequest() ->
    {400,[],
        {xmlelement, "html", [{"xmlns", "http://www.w3.org/1999/xhtml"}, {"xml:lang", "en"}],[
            {xmlelement, "head", [], [
                {xmlelement, "title", [], [
                    {xmlcdata, "Bad Request"}
                ]}
            ]},
            {xmlelement, "body", [], [
                {xmlelement, "p", [], [
                    {xmlcdata, "Bad Request"}
                ]}
            ]}
        ]}
    }.
    
%%%----------------------------------------------------------------------
%%% BEHAVIOUR CALLBACKS
%%%----------------------------------------------------------------------
    
start(_Host, _Opts) ->
    ok.

stop(_Host) ->
    ok.
