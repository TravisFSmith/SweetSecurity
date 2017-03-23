from flask_mail import Mail, Message

def emailUser(mail,subject,recipient,body):
	if recipient is not None:
		try:
			msg = Message(subject, recipients=[recipient])
			msg.html = body
			mail.send(msg)
			return "email sent"
		except Exception, e:
			return str(e)
	else:
		return "No email configured"
	
