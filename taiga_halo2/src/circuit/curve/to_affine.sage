# This code creates a point in jacobian coordinates
p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
Fp = GF(p)
E = EllipticCurve(Fp, [0,5])
# A random point P of the curve
P = E([1681469982790059970373664030117006074505504870098410488796634237003291674854,10219160695633417915856046187543024269086042488170073842930935406863680832869])
# We transform it in jacobian coordinates with a random z
z = Fp(37836369260799143566725228675687178712878544165895752975793672844149387211)
p_x = P[0] * z**2
p_y = P[1] * z**3
p_z = z
for (c,name) in zip([p_x, p_y, p_z], ['p_x','p_y', 'p_z']):
    d = ZZ(c)
    # print rust code
    print("let {} = Fp::from_raw([".format(name))
    while d >0 :
        print("\t{}, ".format(d%(1<<64)))
        d = d >> 64
    print(']);')
