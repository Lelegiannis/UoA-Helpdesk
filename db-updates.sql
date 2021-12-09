UPDATE ost_role SET name='View' WHERE id=4;
INSERT INTO ost_role VALUES
(5,1,'Resolve','{"ticket.close":1,"task.close":1,"task.create":1,"task.delete":1,"task.edit":1,"task.reply":1}',NULL,NOW(),NOW()),
(6,1,'Assign','{"ticket.assign":1,"ticket.release":1,"ticket.transfer":1,"task.assign":1,"task.transfer":1,"ticket.edit":1}',NULL,NOW(),NOW()),
(7,1,'Full','{"ticket.assign":1,"ticket.close":1,"ticket.delete":1,"ticket.edit":1,"ticket.refer":1,"ticket.release":1,"ticket.transfer":1,"task.assign":1,"task.close":1,"task.create":1,"task.delete":1,"task.edit":1,"task.reply":1,"task.transfer":1,"canned.manage":1}',NULL,NOW(),NOW());
