import { DemoQueue, SqliteQueueStore, QueueError } from './queue.mjs';
import { modelConfiguration, requireEnabledModel, ModelError } from './models.mjs';

export class Scheduler {
  constructor(ctx, env) {
    this.pending = Promise.resolve();
    this.ctx = ctx;
    this.env = env;
    this.queue = new DemoQueue(new SqliteQueueStore(ctx.storage), {capacity:Number(env.DEMO_CAPACITY || 1),modelIds:modelConfiguration(env).models.map(model=>model.id)});
    ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS demo_admissions (visitor_ip TEXT PRIMARY KEY, window INTEGER NOT NULL, count INTEGER NOT NULL)');
  }
  // Serialize queue mutation and alarm reads/writes together. Otherwise a
  // suspended alarm update could overwrite a newer request's deadline.
  serialize(operation) {
    const result = this.pending.then(operation);
    this.pending = result.catch(() => {});
    return result;
  }
  fetch(request) {
    return this.serialize(() => this.handle(request));
  }
  async handle(request) {
    try {
      const { action, args = [] } = await request.json();
      const now = Date.now();
      let result;
      if (action === 'admit') {
        const [visitorHash, ipHash, modelId] = args;
        if(args.length!==3)throw new QueueError('invalid_admission',400);
        requireEnabledModel(modelId,this.env);
        if (!/^[a-f0-9]{64}$/.test(ipHash)) throw new QueueError('invalid_admission',400);
        this.ctx.storage.transactionSync(() => {
          const window = Math.floor(now / 3_600_000);
          this.ctx.storage.sql.exec('DELETE FROM demo_admissions WHERE window < ?',window);
          const existing = this.ctx.storage.sql.exec('SELECT count FROM demo_admissions WHERE visitor_ip = ? AND window = ?',ipHash,window).toArray();
          if ((existing[0]?.count || 0) >= 5) throw new QueueError('demo_admission_limit',429);
          const count = this.ctx.storage.sql.exec('SELECT COUNT(*) AS n FROM demo_admissions').toArray()[0].n;
          if (count >= 4096 && !existing.length) throw new QueueError('demo_admission_limit',429);
          this.ctx.storage.sql.exec('INSERT INTO demo_admissions(visitor_ip,window,count) VALUES(?,?,1) ON CONFLICT(visitor_ip) DO UPDATE SET window=excluded.window,count=count+1',ipHash,window);
        });
        // Charge a bot-verified admission attempt before queue allocation. Both
        // operations are synchronous; no nested SQLite transaction is needed.
        // A queue-full failure retains the admission charge, never extra access.
        result = this.queue.join(visitorHash,modelId,now,0);
      } else {
        const methods = {
          status:()=>this.queue.status(args[0],now), cancel:()=>this.queue.cancel(args[0],now),
          work:()=>this.queue.work(now), report:()=>this.queue.report(args[0],now),
          authorize:()=>this.queue.authorize(args[0],now), reserveChat:()=>this.queue.reserveChat(args[0],args[1],now),
          finishChat:()=>this.queue.finishChat(args[0],args[1],now),
        };
        if (!Object.hasOwn(methods,action)) throw new QueueError('unknown_scheduler_action',404);
        result = methods[action]();
      }
      await this.arm(action === 'work' ? result.next_alarm_at : undefined);
      return Response.json(result);
    } catch (error) {
      if (error instanceof QueueError || error instanceof ModelError) return Response.json({error:error.code},{status:error.status});
      return Response.json({error:'scheduler_unavailable'},{status:503});
    }
  }
  async arm(nextAlarmAt) {
    // work() also reserves idle slots atomically. Controller remains the only
    // actor allowed to create or acknowledge Kubernetes resources.
    // A work request already performed that sweep and returned its deadline.
    const desired = nextAlarmAt === undefined ? this.queue.work(Date.now()).next_alarm_at : nextAlarmAt;
    const current = await this.ctx.storage.getAlarm();
    if (current === desired) return;
    if (desired !== null) await this.ctx.storage.setAlarm(desired);
    else if (current !== null) await this.ctx.storage.deleteAlarm();
  }
  alarm() { return this.serialize(() => this.arm()); }
}
