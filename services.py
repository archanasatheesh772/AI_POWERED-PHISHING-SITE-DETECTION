from datetime import datetime
from db import db, AuditLog

class LoggerService:
    @staticmethod
    def log_action(action, user_id, details=None):
        try:
            audit_log = AuditLog(
                action=action,
                user_id=user_id,
                details=details
            )
            db.session.add(audit_log)
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            print(f"Error logging action: {str(e)}")
            return False