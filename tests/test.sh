SECRET=JRSSAVCPKRICAY3BEBSW45TPNFSSAZDVEBYGC5DF
rc=0

echo -en " Test 1: \033[1mModule do nothing without auth_totp_realm directive\033[0m... "
http_code=$( curl -sio /tmp/last -w "%{http_code}" http://localhost:8080/public/index.html )
[ "${http_code}" == "200" ] || echo -e "❌ 033[1;31mFAILED\033[0m (expected 200, but got ${http_code})"
[ "${http_code}" == "200" ] && echo -e "✅ \033[1;32mPASSED\033[0m"
echo "::group::Response from nginx"
cat /tmp/last
echo "::endgroup::" 
[ "${http_code}" == "200" ] || rc=1

echo -en " Test 2: \033[1mauth_totp_realm 'something' block access\033[0m... "
http_code=$( curl -sio /tmp/last -w "%{http_code}" http://localhost:8080/priv6d30s/index.html )
[ "${http_code}" == "401" ] || echo -e "❌ \033[1;31mFAILED\033[0m (expected 401, but got ${http_code})"
[ "${http_code}" == "401" ] && echo -e "✅ \033[1;32mPASSED\033[0m"
echo "::group::Response from nginx"
cat /tmp/last
echo "::endgroup::" 
[ "${http_code}" == "401" ] || rc=2

echo -en " Test 3: \033[1mauth_totp_realm 'something' block access\033[0m... "
http_code=$( curl -sio /tmp/last -w "%{http_code}" http://localhost:8080/priv8d60s/index.html )
[ "${http_code}" == "401" ] || echo -e "❌ \033[1;31mFAILED\033[0m (expected 401, but got ${http_code})"
[ "${http_code}" == "401" ] && echo -e "✅ \033[1;32mPASSED\033[0m"
echo "::group::Response from nginx"
cat /tmp/last
echo "::endgroup::" 
[ "${http_code}" == "401" ] || rc=3

echo -en " Test 4: \033[1mauth_totp_realm off allow access of a subfolder\033[0m... "
http_code=$( curl -sio /tmp/last -w "%{http_code}" http://localhost:8080/priv6d30s/public/index.html )
[ "${http_code}" == "200" ] || echo -e "❌ \033[1;31mFAILED\033[0m (expected 200, but got ${http_code})"
[ "${http_code}" == "200" ] && echo -e "✅ \033[1;32mPASSED\033[0m"
echo "::group::Response from nginx"
cat /tmp/last
echo "::endgroup::" 
[ "${http_code}" == "200" ] || rc=4

echo -en " Test 5: \033[1mTest a valid standard token (6 digits / 30sec)\033[0m... "
http_code=$( curl -u admin:$( python tests/getOTP.py ${SECRET} ) -sio /tmp/last -w "%{http_code}" http://localhost:8080/priv6d30s/index.html )
[ "${http_code}" == "200" ] || echo -e "❌ \033[1;31mFAILED\033[0m (expected 200, but got ${http_code})"
[ "${http_code}" == "200" ] && echo -e "✅ \033[1;32mPASSED\033[0m"
echo "::group::Response from nginx"
cat /tmp/last
echo "::endgroup::" 
[ "${http_code}" == "200" ] || rc=5

echo -en " Test 6: \033[1mTest a valid non-standard token (8 digits / 60sec)\033[0m... "
http_code=$( curl -u admin:$( python tests/getOTP.py ${SECRET} -d 60 -l 8 ) -sio /tmp/last -w "%{http_code}" http://localhost:8080/priv8d60s/index.html )
[ "${http_code}" == "200" ] || echo -e "❌ \033[1;31mFAILED\033[0m (expected 200, but got ${http_code})"
[ "${http_code}" == "200" ] && echo -e "✅ \033[1;32mPASSED\033[0m"
echo "::group::Response from nginx"
cat /tmp/last
echo "::endgroup::" 
[ "${http_code}" == "200" ] || rc=6

echo -en " Test 7: \033[1mA wrong user with a valid standard token (6 digits / 30sec) is reject\033[0m... "
http_code=$( curl -u dummy:$( python tests/getOTP.py ${SECRET} ) -sio /tmp/last -w "%{http_code}" http://localhost:8080/priv6d30s/index.html )
[ "${http_code}" == "401" ] || echo -e "❌ \033[1;31mFAILED\033[0m (expected 401, but got ${http_code})"
[ "${http_code}" == "401" ] && echo -e "✅ \033[1;32mPASSED\033[0m"
echo "::group::Response from nginx"
cat /tmp/last
echo "::endgroup::" 
[ "${http_code}" == "401" ] || rc=7

echo -en " Test 8: \033[1mA wrong user with a valid non-standard token (8 digits / 60sec) is reject\033[0m "
http_code=$( curl -u dummy:$( python tests/getOTP.py ${SECRET} -d 60 -l 8 ) -sio /tmp/last -w "%{http_code}" http://localhost:8080/priv8d60s/index.html )
[ "${http_code}" == "401" ] || echo -e "❌ \033[1;31mFAILED\033[0m (expected 401, but got ${http_code})"
[ "${http_code}" == "401" ] && echo -e "✅ \033[1;32mPASSED\033[0m"
echo "::group::Response from nginx"
cat /tmp/last
echo "::endgroup::" 
[ "${http_code}" == "401" ] || rc=8
exit $rc
