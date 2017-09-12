use CGI;
use CGI::Cookie;
%cookies = CGI::Cookie->fetch;
my $cas_token = $cookies{'MOD_AUTH_CAS'}->value;
unlink glob "/path-to-MOD_AUTH_CAS-cache-file/$cas_token";
my $cgi = new CGI;
print $cgi->redirect('https://sso.yourdomain.com/logout?service=http://otrs.yourdomain.com/');
exit(0);
