
```markdown
# Bounty-Script

## Usage

### Basic Scan:
```bash
./recon.sh example.com
```

### With Notifications:
```bash
SLACK_WEBHOOK="https://hooks.slack.com/services/..." ./recon.sh example.com
```

### CI/CD Mode:
```bash
CI_MODE=true AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... ./recon.sh target.com
```

### Custom Blind XSS:
```bash
BLIND_XSS="https://your.interact.sh" ./recon.sh example.org
```
```
