# 📡 Detection Query Pack

This folder contains starter KQL queries to help defenders monitor the same control-plane abuse themes highlighted by the scanner.

Maintained by **Mahdi Hedhli** and **42 Corp**.

## Included Queries

| Query | Purpose |
| --- | --- |
| [`global-admin-role-assignment.kql`](global-admin-role-assignment.kql) | Detects activity related to Global Administrator role assignment and eligibility changes |
| [`privileged-role-assignment-activity.kql`](privileged-role-assignment-activity.kql) | Flags recent high-value role grants and activations |
| [`admin-consent-high-risk-apps.kql`](admin-consent-high-risk-apps.kql) | Highlights risky admin consent and high-impact application permission changes |
| [`intune-destructive-actions.kql`](intune-destructive-actions.kql) | Surfaces high-impact Intune device actions such as wipe, retire, or delete operations |

## Notes

- These queries are starter logic, not drop-in perfection.
- Field names and activity names can vary by connector, table source, and export path.
- Tune allowlists, role names, and lookback windows for your tenant before promoting them to production detections.
