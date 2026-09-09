import { DurableObject } from 'cloudflare:workers';
import { Scheduler } from './scheduler.mjs';
import { Leads } from './leads.mjs';
import { handleRequest } from './http.mjs';

export class DemoScheduler extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.scheduler = new Scheduler(ctx, env);
  }
  fetch(request) { return this.scheduler.fetch(request); }
  alarm() { return this.scheduler.alarm(); }
}

export class LeadInbox extends DurableObject {
  constructor(ctx,env) { super(ctx,env); this.leads=new Leads(ctx,env); }
  fetch(request) { return this.leads.fetch(request); }
  alarm() { return this.leads.alarm(); }
}

export default {fetch:handleRequest};
