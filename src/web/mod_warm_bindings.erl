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

-record(binding, {jid, sid, rid}).

%%%----------------------------------------------------------------------
%%% REQUEST HANDLERS
%%%----------------------------------------------------------------------

process([], #request{auth = Auth, ip = IP, method = 'POST', data = Data}) ->
    case auth_admin(Auth) of
        success -> 
            ?INFO_MSG("Params ~p",[Data]),
            {value,{_,SJID}} = lists:keysearch(jid,      1, param_decode(Data)),
            {value,{_,Pass}} = lists:keysearch(password, 1, param_decode(Data)),
            case is_list(SJID) andalso is_list(Pass) of
                true  ->
                    case bind(SJID, Pass, IP) of
                        false   -> badrequest();
                        Binding -> success(Binding)
                    end;
                false -> badrequest()
            end;
        forbidden    -> forbidden();
        unauthorized -> unauthorized()
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
    
bind(SJID, Password, IP) ->
    #jid{user = User, server = Server, resource = Resource} = jlib:string_to_jid(SJID),
    RidSessionCreate  = list_to_integer(randoms:get_string()),
    RidAuth           = RidSessionCreate  + 1,
    RidSessionRestart = RidAuth           + 1,
    RidResourceBind   = RidSessionRestart + 1,
    RidSessionRequest = RidResourceBind   + 1,
    RidNext           = RidSessionRequest + 1,
    
    {xmlelement, "body", Attrs1, _ } = process_request("<body rid='"++integer_to_list(RidSessionCreate)++"' xmlns='http://jabber.org/protocol/httpbind' to='"++Server++"' xml:lang='en' wait='60' hold='1' window='5' content='text/xml; charset=utf-8' ver='1.6' xmpp:version='1.0' xmlns:xmpp='urn:xmpp:xbosh'/>", IP),
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
                        {xmlelement, "legend",[],[{xmlcdata, "Warm Binding"}]},
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
