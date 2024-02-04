-module(sdp).

-export([parse/1]).
-export_type([service/0]).

-ifdef(TEST).
-include_lib("proper/include/proper.hrl").
-endif.

-record(service, { version :: version(),
                   origin :: origin(),
                   session :: session(),
                   information :: information(),
                   uri :: uri(),
                   email :: email(),
                   phone :: phone(),
                   connection :: connection(),
                   bandwidth :: list(bandwidth()),
                   time :: list(timestamp()),
                   key :: key() | nothing,
                   attributes :: list(attribute()),
                   media :: list(media())
                 }).

-record(origin, {username :: string(),
                 sessionID :: integer(),
                 sessionVersion :: integer(),
                 netType :: string(),
                 addrType :: string(),
                 unicastAddress :: network_address()
                }).
-record(session, {name :: string()}).
-record(connection, {network_type :: network_type(),
                     address_type :: address_type(),
                     connection :: network_address()
                    }).
-record(bandwidth, {bwtype :: string(),
                    bandwidth :: integer()
                   }).
-record(time, {start_time :: zero | erlang:timestamp(),
               stop_time :: zero | erlang:timestamp(),
               repeat :: repeat() | nothing
              }).
-record(media_field, {media :: string(),
                      port :: media_port(),
                      protocol :: string(),
                      format :: integer()}).
-record(media_desc, {media,
                     info,
                     connection,
                     bandwidth,
                     key,
                     attributes}).

-type service_description() :: list(string()).

-opaque service() :: #service{}.
-type version() :: non_neg_integer().
-type origin() :: #origin{}.
-type session() :: #session{}.
-type information() :: string() | nothing.
-type uri() :: uri_string:uri_map() | nothing.
-type email() :: string().
-type phone() :: string().
-type connection() :: #connection{} | nothing.
-type bandwidth() :: #bandwidth{}.
-type timestamp() :: #time{}.
-type key() :: prompt
             | {clear, string()}
             | {base64, string()}
             | {uri, string()}
             | nothing.
-type attribute() :: {attribute, string()}
                   | {attribute_key_val, string(), string()}.
-type media() :: #media_desc{}.

-type network_type() :: string().
-type address_type() :: string().
-type network_address() :: {ip4, {pos_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()}}
                         | {ip6, {pos_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()}}
                         | {fqdn, string()}
                         | {extn_addr, string()}.

-type media_port() :: {port, pos_integer()}
                    | {port_with_slash, pos_integer(), pos_integer()}.
-type media_field() :: #media_field{}.

-type interval() :: {integer(), day | hour | minute | second}.
-type repeat() :: {pos_integer(), non_neg_integer(), interval() | nothing}.

%%%===========
%%% Public API
%%%===========

-spec parse(bitstring() | string()) -> service() | parse_fail.
parse(String) when is_binary(String) ->
    parse(binary_to_list(String));
parse(String) when is_list(String) ->
    parse_sdp(string:split(String, "\r\n", all)).

%%%==========
%%% Internals
%%%==========

% Parse version (required field)
-spec parse_sdp(service_description()) -> service() | parse_fail.
parse_sdp([[$v, $= | V] | Rest]) ->
    case string:to_integer(V) of
        {error, _} ->
            parse_fail;
        {Version, []} ->
            parse_sdp(Version, Rest)
    end;
parse_sdp(_) ->
    parse_fail.

% Parse origin (required field)
-spec parse_sdp(version(), service_description()) -> service() | parse_fail.
parse_sdp(V, [[$o, $= | O] | Rest]) ->
    case parse_origin(O) of
        {ok, Origin} ->
            parse_sdp(V, Origin, Rest);
        parse_fail ->
            parse_fail
    end;
parse_sdp(_, _) ->
    parse_fail.

% Parse session (required field)
-spec parse_sdp(version(), origin(), service_description()) -> service() | parse_fail.
parse_sdp(V, O, [[$s, $= | S] | Rest]) ->
    case parse_session(S) of
        {ok, Session} ->
            parse_sdp(V, O, Session, Rest);
        parse_fail ->
            parse_fail
    end;
parse_sdp(_, _, _) ->
    parse_fail.

-spec parse_sdp(version(), origin(), session(), service_description()) -> service() | parse_fail.
parse_sdp(V, O, S, [[$i, $= | I] | Rest]) ->
    case parse_information(I) of
        {ok, Info} ->
            parse_sdp(V, O, S, Info, Rest);
        parse_fail ->
            parse_fail
    end;
parse_sdp(V, O, S, Rest) ->
    parse_sdp(V, O, S, nothing, Rest).

-spec parse_sdp(version(), origin(), session(), information(), service_description()) -> service() | parse_fail.
parse_sdp(V, O, S, I, [[$u, $= | U] | Rest]) ->
    case parse_uri(U) of
        {ok, URI} ->
            parse_sdp(V, O, S, I, URI, [], Rest);
        parse_fail ->
            parse_fail
    end;
parse_sdp(V, O, S, I, Rest) ->
    parse_sdp(V, O, S, I, nothing, [], Rest).

-spec parse_sdp(version(), origin(), session(), information(), uri(), list(email()), service_description()) -> service() | parse_fail.
parse_sdp(V, O, S, I, U, Es, [[$e, $= | E] | Rest]) ->
    case parse_email(E) of
        {ok, Email} ->
            parse_sdp(V, O, S, I, U, Es ++ [Email], Rest);
        parse_fail ->
            parse_fail
    end;
parse_sdp(V, O, S, I, U, Es, Rest) ->
    parse_sdp(V, O, S, I, U, Es, [], Rest).

-spec parse_sdp(version(), origin(), session(), information(), uri(), list(email()), list(phone()), service_description()) -> service() | parse_fail.
parse_sdp(V, O, S, I, U, Es, Ps, [[$p, $= | P] | Rest]) ->
    case parse_phone(P) of
        {ok, Phone} ->
            parse_sdp(V, O, S, I, U, Es, Ps ++ [Phone], Rest);
        parse_fail ->
            parse_fail
    end;
parse_sdp(V, O, S, I, U, Es, Ps, [[$c, $= | C] |Rest]) ->
    case parse_connection(C) of
        {ok, Conn} ->
            parse_sdp(V, O, S, I, U, Es, Ps, Conn, [], Rest);
        parse_fail ->
            parse_fail
    end;
parse_sdp(V, O, S, I, U, Es, Ps, Rest) ->
    parse_sdp(V, O, S, I, U, Es, Ps, nothing, [], Rest).

-spec parse_sdp(version(), origin(), session(), information(), uri(), list(email()), list(phone()), connection() | nothing, list(bandwidth()), service_description()) -> service() | parse_fail.
parse_sdp(V, O, S, I, U, Es, Ps, C, Bs, [[$b, $= | B] | Rest]) ->
    case parse_bandwidth(B) of
        {ok, Band} ->
            parse_sdp(V, O, S, I, U, Es, Ps, C, Bs ++ [Band], Rest);
        parse_fail ->
            parse_fail
    end;
parse_sdp(V, O, S, I, U, Es, Ps, C, Bs, [[$t, $= | T] | Rest]) ->
    case parse_time(T, Rest) of
        {ok, Time, Rest2} ->
            parse_sdp(V, O, S, I, U, Es, Ps, C, Bs, [Time], Rest2);
        parse_fail ->
            parse_fail
    end;
parse_sdp(_, _, _, _, _, _, _, _, _, _) ->
    parse_fail.

-spec parse_sdp(version(), origin(), session(), information(), uri(), list(email()), list(phone()), connection() | nothing, list(bandwidth()), list(timestamp()), service_description()) -> service() | parse_fail.
parse_sdp(V, O, S, I, U, Es, Ps, C, Bs, Ts, [[$t, $= | T] | Rest])->
    case parse_time(T, Rest) of
        {ok, Time, Rest2} ->
            parse_sdp(V, O, S, I, U, Es, Ps, C, Bs, Ts ++ [Time], Rest2);
        parse_fail ->
            parse_fail
    end;
parse_sdp(V, O, S, I, U, Es, Ps, C, Bs, Ts, [[$k, $= | K] | Rest])->
    case parse_key(K) of
        {ok, Key} ->
            parse_sdp(V, O, S, I, U, Es, Ps, C, Bs, Ts, Key, [], Rest);
        parse_fail ->
            parse_fail
    end;
parse_sdp(V, O, S, I, U, Es, Ps, C, Bs, Ts, Rest) ->
    parse_sdp(V, O, S, I, U, Es, Ps, C, Bs, Ts, nothing, [], Rest).

-spec parse_sdp(version(), origin(), session(), information(), uri(), list(email()), list(phone()), connection() | nothing, list(bandwidth()), list(timestamp()), key(), list(attribute()), service_description()) -> service() | parse_fail.
parse_sdp(V, O, S, I, U, Es, Ps, C, Bs, Ts, K, As, [[$a, $= | A] | Rest]) ->
    case parse_attribute(A) of
        {ok, Attr} ->
            parse_sdp(V, O, S, I, U, Es, Ps, C, Bs, Ts, K, As ++ [Attr], Rest);
        parse_fail ->
            parse_fail
    end;
parse_sdp(V, O, S, I, U, Es, Ps, C, Bs, Ts, K, As, Rest) ->
    parse_sdp(V, O, S, I, U, Es, Ps, C, Bs, Ts, K, As, [], Rest).

-spec parse_sdp(version(), origin(), session(), information(), uri(), list(email()), list(phone()), connection() | nothing, list(bandwidth()), list(timestamp()), key(), list(attribute()), list(media()), service_description()) -> service() | parse_fail.
parse_sdp(V, O, S, I, U, Es, Ps, C, Bs, Ts, K, As, Ms, [[$m, $= | M] | Rest]) ->
    case parse_media(M, Rest) of
        {ok, Media, Rest2} ->
            parse_sdp(V, O, S, I, U, Es, Ps, C, Bs, Ts, K, As, Ms ++ [Media], Rest2);
        parse_fail ->
            parse_fail
    end;
parse_sdp(V, O, S, I, U, Es, Ps, C, Bs, Ts, K, As, Ms, _Rest) ->
    #service{version = V,
             origin = O,
             session = S,
             information = I,
             uri = U,
             email = Es,
             phone = Ps,
             connection = C,
             bandwidth = Bs,
             time = Ts,
             key = K,
             attributes = As,
             media = Ms}.

-spec parse_origin(string()) -> {ok, origin()} | parse_fail.
parse_origin(OriginString) ->
    [Username, SessionID, SessionVersion, NetType, AddrType, UnicastAddress] = string:split(OriginString, " ", all),
    parse_origin(Username, SessionID, SessionVersion, NetType, AddrType, UnicastAddress).

-spec parse_origin(string(), string(), string(), string(), string(), string()) -> {ok, origin()} | parse_fail.
parse_origin(U, S, SV, N, A, UA) ->
    UParsed = nonWSString(U),
    SParsed = string:to_integer(S),
    SVParsed = string:to_integer(SV),
    NParsed = token(N, ["IN", "TN", "ATM", "PSTN"]),
    AParsed = token(A, ["IP4", "IP6"]),
    UAParsed = parse_network_address(UA),
    case [UParsed, SParsed, SVParsed, NParsed, AParsed, UAParsed] of
        [{ok, UserName},
         {SessionID, []},
         {SessionVersion, []},
         {ok, NetType},
         {ok, AddrType},
         {ok, UnicastAddress}] ->
            {ok, #origin{username = UserName,
                         sessionID = SessionID,
                         sessionVersion = SessionVersion,
                         netType = NetType,
                         addrType = AddrType,
                         unicastAddress = UnicastAddress}};
        _ ->
            parse_fail
    end.

-spec parse_session(string()) -> {ok, session()} | parse_fail.
parse_session(S) when length(S) > 0 ->
    {ok, #session{name = S}};
parse_session(_) ->
    parse_fail.

-spec parse_information(string()) -> {ok, information()} | parse_fail.
parse_information(S) when length(S) > 0 ->
    {ok, S};
parse_information(_) ->
    parse_fail.

-spec parse_uri(string()) -> {ok, uri()} | parse_fail.
parse_uri(U) ->
    case uri_string:parse(U) of
        {error, _, _} ->
            parse_fail;
        URI ->
            {ok, URI}
    end.

-spec parse_bandwidth(string()) -> {ok, bandwidth()} | parse_fail.
parse_bandwidth(B) ->
    Parts = string:split(B, ":", all),
    case length(Parts) of
        2 ->
            [BWType, Bandwidth] = Parts,
            case token(BWType, ["CT", "AS"]) of
                {ok, Type} ->
                    case string:to_integer(Bandwidth) of
                        {error, _} ->
                            parse_fail;
                        {BW, []} ->
                            {ok, #bandwidth{bwtype = Type, bandwidth=BW}};
                        _ ->
                            parse_fail
                    end;
                parse_fail ->
                    parse_fail
            end;
        _ ->
            parse_fail
    end.

-spec parse_time(string(), service_description()) -> {ok, timestamp(), service_description()} | parse_fail.
parse_time(T, Rest) ->
    Parts = string:split(T, " ", all),
    case length(Parts) of
        2 ->
            [Start, Stop] = Parts,
            StartT = time_for(Start),
            StopT = time_for(Stop),
            case StartT of
                parse_fail ->
                    parse_fail;
                _ ->
                    case StopT of
                        parse_fail ->
                            parse_fail;
                        _ ->
                            case Rest of
                                [[$r, $= | R] | Rest2] ->
                                    case parse_repeat(R) of
                                        {ok, Repeat} ->
                                            {ok, #time{start_time = StartT, stop_time = StopT, repeat = Repeat}, Rest2};
                                        _ ->
                                            parse_fail
                                    end;
                                _ ->
                                    {ok, #time{start_time = StartT, stop_time = StopT, repeat = nothing}, Rest}
                            end
                    end
            end
    end.

-spec time_for(string()) -> zero | erlang:timestamp() | parse_fail.
time_for(String) ->
    case String of
        "0" ->
            zero;
        _ ->
            Mod = 1000000,
            case string:to_integer(String) of
                {I, []} ->
                    {I div Mod div Mod, I div Mod rem Mod, I rem Mod};
                _ ->
                    parse_fail
            end
    end.

-spec parse_repeat(string()) -> {ok, {pos_integer(), non_neg_integer(), interval() | nothing}} | parse_fail.
parse_repeat(Repeat) ->
    Parts = string:split(Repeat, " ", all),
    case length(Parts) of
        3 ->
            [Interval1, Interval2, Typed] = Parts,
            case string:to_integer(Interval1) of
                {error, _} ->
                    parse_fail;
                {I1, []} ->
                    if
                        I1 > 0 ->
                            case string:to_integer(Interval2) of
                                {error, _} ->
                                    parse_fail;
                                {I2, []} ->
                                    if
                                        I2 >= 0 ->
                                            case parse_interval(Typed) of
                                                {ok, T} ->
                                                    {ok, {I1, I2, T}};
                                                parse_fail ->
                                                    parse_fail
                                            end;
                                        true ->
                                            parse_fail
                                    end;
                                _ ->
                                    parse_fail
                            end;
                        true ->
                            parse_fail
                    end;
                _ ->
                    parse_fail
            end;
        2 ->
            [Interval1, Interval2] = Parts,
            case string:to_integer(Interval1) of
                {error, _} ->
                    parse_fail;
                {I1, []} ->
                    if
                        I1 > 0 ->
                            case string:to_integer(Interval2) of
                                {error, _} ->
                                    parse_fail;
                                {I2, []} ->
                                    if
                                        I2 >= 0 ->
                                            {ok, {I1, I2, nothing}};
                                        true ->
                                            parse_fail
                                    end
                            end;
                        true ->
                            parse_fail
                    end
            end;
        _ ->
            parse_fail
    end.

parse_interval(Interval) ->
    case string:to_integer(Interval) of
        {error, _} ->
            parse_fail;
        {I, "d"} ->
            if
                I > 0 -> {ok, {I, day}};
                true  -> parse_fail
            end;
        {I, "h"} ->
            if
                I > 0 -> {ok, {I, hour}};
                true  -> parse_fail
            end;
        {I, "m"} ->
            if
                I > 0 -> {ok, {I, minute}};
                true  -> parse_fail
            end;
        {I, "s"} ->
            if
                I > 0 -> {ok, {I, second}};
                true  -> parse_fail
            end;
        {I, []} ->
            if
                I > 0 -> {ok, {I, second}};
                true  -> parse_fail
            end;
        _ ->
            parse_fail
    end.

-spec parse_key(string()) -> {ok, key()} | parse_fail.
parse_key(Key) ->
    case Key of
        "prompt" ->
            {ok, prompt};
        [$c, $l, $e, $a, $r, $: | Rest] ->
            {ok, {clear, Rest}};
        [$b, $a, $s, $e, $6, $4, $: | Rest] ->
            {ok, {base64, Rest}};
        [$u, $r, $i, $: | Rest] ->
            {ok, {uri, Rest}};
        _ ->
            parse_fail
    end.

-spec parse_media(string(), service_description()) -> {ok, media(), service_description()} | parse_fail.
parse_media(M, Rest) ->
    Parts = string:split(M, " ", all),
    if
        length(Parts) >= 3 ->
            [Media, Port, Proto | Fmt] = Parts,
            case parse_media_field(Media, Port, Proto, Fmt) of
                {ok, Media2} ->
                    parse_media_additional_lines(Media2, Rest);
                parse_fail ->
                    parse_fail
            end;
        true ->
            parse_fail
    end.

-spec parse_media_additional_lines(media_field(), service_description()) -> {ok, media(), service_description()} | parse_fail.
parse_media_additional_lines(M, [[$i, $= | I] | Rest]) ->
    case parse_information(I) of
        {ok, Info} ->
            parse_media_additional_lines(M, Info, [], Rest);
        parse_fail ->
            parse_fail
    end;
parse_media_additional_lines(M, Rest) ->
    parse_media_additional_lines(M, nothing, [], Rest).

-spec parse_media_additional_lines(media_field(), information(), list(connection()), service_description()) -> {ok, media(), service_description()} | parse_fail.
parse_media_additional_lines(M, I, Cs, [[$c, $= | C] | Rest]) ->
    case parse_connection(C) of
        {ok, Conn} ->
            parse_media_additional_lines(M, I, Cs ++ [Conn], Rest);
        parse_fail ->
            parse_fail
    end;
parse_media_additional_lines(M, I, Cs, Rest) ->
    parse_media_additional_lines(M, I, Cs, [], Rest).

-spec parse_media_additional_lines(media_field(), information(), list(connection()), list(bandwidth()), service_description()) -> {ok, media(), service_description()} | parse_fail.
parse_media_additional_lines(M, I, Cs, Bs, [[$b, $= | B] | Rest]) ->
    case parse_bandwidth(B) of
        {ok, Band} ->
            parse_media_additional_lines(M, I, Cs, Bs ++ [Band], Rest);
        parse_fail ->
            parse_fail
    end;
parse_media_additional_lines(M, I, Cs, Bs, [[$k, $= | K] | Rest]) ->
    case parse_key(K) of
        {ok, Key} ->
            parse_media_additional_lines(M, I, Cs, Bs, Key, [], Rest);
        parse_fail ->
            parse_fail
    end;
parse_media_additional_lines(M, I, Cs, Bs, Rest) ->
    parse_media_additional_lines(M, I, Cs, Bs, nothing, [], Rest).

-spec parse_media_additional_lines(media_field(), information(), list(connection()), list(bandwidth()), key(), list(attribute()), service_description()) -> {ok, media(), service_description()} | parse_fail.
parse_media_additional_lines(M, I, Cs, Bs, K, As, [[$a, $= | A] | Rest]) ->
    case parse_attribute(A) of
        {ok, Attr} ->
            parse_media_additional_lines(M, I, Cs, Bs, K, As ++ [Attr], Rest);
        parse_fail ->
            parse_fail
    end;
parse_media_additional_lines(M, I, Cs, Bs, K, As, Rest) ->
    {ok,
     #media_desc{media = M,
                 info = I,
                 connection = Cs,
                 bandwidth = Bs,
                 key = K,
                 attributes = As},
     Rest}.

-spec parse_media_field(string(), string(), string(), list(string())) -> {ok, media_field()} | parse_fail.
parse_media_field(M, P, Pr, Fmt) ->
    case token(M, ["audio", "video", "text", "image", "application"]) of
        {ok, Media} ->
            PortParts = string:split(P, "/", all),
            case parse_media_portparts(PortParts) of
                {ok, PortSpec} ->
                    case parse_media_proto(Pr) of
                        {ok, Proto} ->
                            case parse_fmt(Fmt) of
                                {ok, Format} ->
                                    {ok, #media_field{media = Media, port = PortSpec, protocol = Proto, format = Format}};
                                parse_fail -> parse_fail
                            end;
                        parse_fail ->
                            parse_fail
                    end;
                parse_fail ->
                    parse_fail
            end;
        parse_fail ->
            parse_fail
    end.

-spec parse_media_portparts(list(string())) -> {ok, media_port()} | parse_fail.
parse_media_portparts([Port]) ->
    case string:to_integer(Port) of
        {I, []} ->
            if
                I > 0, I < 65536 ->
                    {ok, {port, I}};
                true ->
                    parse_fail
            end;
        _ ->
            parse_fail
    end;
parse_media_portparts([Port, Slash]) ->
    case string:to_integer(Port) of
        {I, []} ->
            if
                I > 0, I < 65536 ->
                    case string:to_integer(Slash) of
                        {J, []} ->
                            if
                                J > 0 -> {ok, {port_with_slash, I, J}};
                                true -> parse_fail
                            end;
                        _ ->
                            parse_fail
                    end;
                true ->
                    parse_fail
            end;
        _ ->
            parse_fail
    end;
parse_media_portparts(_) ->
    parse_fail.

-spec parse_media_proto(string()) -> {ok, string()} | parse_fail.
parse_media_proto(Pr) ->
    Parts = string:split(Pr, "/", all),
    case lists:all(fun(X) -> check(nonWSString(X)) end, Parts) of
        true ->
             % TODO: validate the protocols declared
            {ok, Pr};
        false ->
            parse_fail
    end.
check({ok, _}) -> true;
check(_) -> false.

-spec parse_fmt(list(string())) -> {ok, integer()} | parse_fail.
parse_fmt([Fmt | []]) ->
    case string:to_integer(Fmt) of
        {I, []} ->
            {ok, I};
        {error, _} ->
            parse_fail
    end;
parse_fmt(_) ->
    parse_fail.

% Email parsing is ignored.  This is a bug, but parsing the email address per
% RFC5322 would be as large as the SDP parser otherwise.
-spec parse_email(string()) -> {ok, email()} | parse_fail.
parse_email(E) when length(E) > 0 ->
    {ok, E};
parse_email(_) ->
    parse_fail.

-spec parse_phone(string()) -> {ok, phone()} | parse_fail.
parse_phone(P) when length(P) > 1 ->
    {ok, P};
parse_phone(_) ->
    parse_fail.

-spec parse_connection(string()) -> {ok, connection()} | parse_fail.
parse_connection(C) ->
    Details = string:split(C, " ", all),
    case length(Details) of
        3 ->
            [N, A, Co] = Details,
            case token(N, ["IN", "TN", "ATM", "PSTN"]) of
                {ok, NetType} ->
                    case token(A, ["IP4", "IP6"]) of
                        {ok, AddrType} ->
                            case parse_network_address(Co) of
                                {ok, Conn} ->
                                    {ok, #connection{network_type = NetType,
                                                     address_type = AddrType,
                                                     connection = Conn}};
                                parse_fail ->
                                    parse_fail
                            end;
                        parse_fail ->
                            parse_fail
                    end;
                parse_fail ->
                    parse_fail
            end;
        _ ->
            parse_fail
    end.

% TODO: RFC8859 defines these attributes; this can be exhaustive.
% Today, it is not.
-spec parse_attribute(string()) -> {ok, attribute()} | parse_fail.
parse_attribute(A) ->
    Parts = string:split(A, ":"),
    case Parts of
        [Attr] ->
            case lists:all(fun(X) -> (X > 0) and (X < 128) and (X =/= 10) and (X =/= 13) end, Attr) of
                true ->
                    {ok, {attribute, Attr}};
                false ->
                    parse_fail
            end;
        [Name, Val] ->
            case lists:all(fun(X) -> ((X > 0) and (X < 128) and (X =/= 10) and (X =/= 13)) end, Name) of
                true ->
                    case lists:all(fun(X) -> (X =/= 0) and (X =/= 10) and (X =/= 13) end, Val) of
                        true ->
                            {ok, {attribute_key_val, Name, Val}};
                        false ->
                            parse_fail
                    end;
                false ->
                    parse_fail
            end;
        _ ->
            parse_fail
    end.

-spec nonWSString(string()) -> {ok, string()} | parse_fail.
nonWSString(String) ->
    case re:run(String, "\\s") of
        {match, _} -> parse_fail;
        nomatch -> {ok, String}
    end.

-spec token(string(), list(string())) -> {ok, string()} | parse_fail.
token(String, Allowed) ->
    case lists:member(String, Allowed) of
        true -> {ok, String};
        false -> parse_fail
    end.

-spec parse_network_address(string()) -> {ok, network_address()} | parse_fail.
parse_network_address(UA) ->
    case inet:parse_ipv4strict_address(UA) of
        {ok, IP} -> {ok, {ip4, IP}};
        _ ->
            case inet:parse_ipv6strict_address(UA) of
                {ok, IP} -> {ok, {ip6, IP}};
                _ ->
                    case verify_fqdn(nonWSString(UA)) of
                        {ok, String} -> {ok, {fqdn, String}};
                        parse_fail ->
                            case nonWSString(UA) of
                                {ok, S} ->
                                    {ok, {extn_addr, S}};
                                parse_fail ->
                                    parse_fail
                            end
                    end
            end
    end.

-spec verify_fqdn({ok, string()}) -> {ok, string()} | parse_fail.
verify_fqdn({ok, FQDN}) ->
    case inet:gethostbyname(FQDN) of
        {ok, _} ->
            {ok, FQDN};
        _ ->
            parse_fail
    end;
verify_fqdn(_) ->
    parse_fail.
