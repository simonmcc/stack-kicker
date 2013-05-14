#!/bin/bash

cat > /var/www/index.html <<HEREDOC
<html><body><h1>Stack-Kicker was 'ere!</h1>
<p>This file is dropped in place by a shell script passed to the host via cloud-init</p>
<p>The web server software is running but no content has been added, yet.</p>
</body></html>
HEREDOC
