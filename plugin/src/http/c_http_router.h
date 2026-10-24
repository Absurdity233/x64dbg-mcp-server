#pragma once

#include <string>
#include <vector>
#include <functional>

#include "http/s_http_request.h"
#include "http/s_http_response.h"

// Route handler function signature
using route_handler_t = std::function<s_http_response(const s_http_request&)>;

class c_http_router {
public:
    // Register a route
    void add_route(const std::string& method, const std::string& path, route_handler_t handler);

    // Convenience helpers
    void get(const std::string& path, route_handler_t handler);
    void post(const std::string& path, route_handler_t handler);

    // Dispatch a request to the appropriate handler
    [[nodiscard]] s_http_response dispatch(const s_http_request& request) const;

    // Every registered route as "METHOD /path", in registration order.
    //
    // Routes are only ever stored here, so a manifest built from this list
    // cannot drift from what the plugin actually serves. The server checks it
    // against the routes its tools call, which turns a plugin/server version
    // mismatch into a startup warning instead of a mysterious 404 mid-session.
    [[nodiscard]] std::vector<std::string> route_manifest() const;

private:
    struct s_route {
        std::string method;
        std::string path;
        route_handler_t handler;
    };

    std::vector<s_route> m_routes;
};
