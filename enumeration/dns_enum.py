import dns.resolver

target_domain = input("Enter the domain to find subdomain: ")
records_type = ["A", "AAAA", "CNAME", "MX", "NS", "TXT","SOA"]

resolver = dns.resolver.Resolver()
for record in records_type:
    try:
        answers = resolver.resolve(target_domain, record)
        print(f"\n{record} Records for {target_domain}:")
        for rdata in answers:
            print(f"- {rdata.to_text()}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        print(f"\nNo {record} record found for {target_domain}.")
