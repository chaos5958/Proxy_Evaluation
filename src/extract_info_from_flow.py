def request(ctx, flow):
    print "URL", flow.request.pretty_url, "TIME", (int)((flow.response.timestamp_end - flow.request.timestamp_start) * 1000)
