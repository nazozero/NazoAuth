// Temporary diagnostic implementation; never a production policy.
use super::*;
use std::{collections::BTreeMap, sync::{Arc, Mutex, OnceLock, atomic::{AtomicU64, Ordering}}, time::Instant, task::{Context, Poll, Wake, Waker}, pin::Pin, future::Future};
use diesel::connection::InstrumentationEvent;
#[derive(Default)]
struct Row { n:u64, acquire_us:u64, hold_us:u64, samples:u64, sample_hold_us:u64, queries:u64, sql_us:u64, commit_us:u64, begin_us:u64, poll_us:u64, ready_us:u64, elapsed_us:u64 }
#[derive(Default)]
struct Ledger { second:u64, rows:BTreeMap<String,Row> }
static LEDGER:OnceLock<Mutex<Ledger>>=OnceLock::new();
static SAMPLE:AtomicU64=AtomicU64::new(0);
fn micros(d:Duration)->u64 {d.as_micros() as u64}
fn record(key:String,apply:impl FnOnce(&mut Row)) {
 let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
 let mut all=LEDGER.get_or_init(Default::default).lock().unwrap();
 if all.second!=now {
  for (key,r) in &all.rows { eprintln!("POOLLEDGER {{\"ts\":{},\"phase\":\"{}\",\"n\":{},\"acquire_us\":{},\"hold_us\":{},\"samples\":{},\"sample_hold_us\":{},\"queries\":{},\"sql_us\":{},\"commit_us\":{},\"begin_us\":{},\"poll_us\":{},\"ready_us\":{},\"elapsed_us\":{}}}",all.second,key,r.n,r.acquire_us,r.hold_us,r.samples,r.sample_hold_us,r.queries,r.sql_us,r.commit_us,r.begin_us,r.poll_us,r.ready_us,r.elapsed_us); }
  all.rows.clear();all.second=now;
 }
 apply(all.rows.entry(key).or_default());
}
#[derive(Default)]
struct QueryTimes { started:Option<Instant>,kind:u8,next_kind:u8,queries:u64,sql_us:u64,commit_us:u64,begin_us:u64 }
pub struct ObservedConnection { inner:Option<Object<AsyncPgConnection>>,start:Instant,acquire_us:u64,phase:String,query:Option<Arc<Mutex<QueryTimes>>> }
impl ObservedConnection {
 pub fn new(mut inner:Object<AsyncPgConnection>,acquire_us:u64,phase:String)->Self {
  let query=if SAMPLE.fetch_add(1,Ordering::Relaxed).is_multiple_of(32) {
   let q=Arc::new(Mutex::new(QueryTimes::default()));let observer=q.clone();
   inner.set_instrumentation(move |event:InstrumentationEvent<'_>| {
    let mut q=observer.lock().unwrap();
    match event {
     InstrumentationEvent::BeginTransaction{..}=>q.next_kind=1,
     InstrumentationEvent::CommitTransaction{..}=>q.next_kind=2,
     InstrumentationEvent::StartQuery{..}=>{q.started=Some(Instant::now());q.kind=q.next_kind;q.next_kind=0;},
     InstrumentationEvent::FinishQuery{..}=>{if let Some(start)=q.started.take(){let us=micros(start.elapsed());q.queries+=1;match q.kind{1=>q.begin_us+=us,2=>q.commit_us+=us,_=>q.sql_us+=us}}},_=>{}
    }
   });Some(q)
  } else {inner.set_instrumentation(|_:InstrumentationEvent<'_>|{});None};
  Self{inner:Some(inner),start:Instant::now(),acquire_us,phase,query}
 }
 pub fn take(mut this:Self)->AsyncPgConnection {Object::take(this.inner.take().unwrap())}
}
impl std::ops::Deref for ObservedConnection {type Target=AsyncPgConnection;fn deref(&self)->&Self::Target{self.inner.as_ref().unwrap()}}
impl std::ops::DerefMut for ObservedConnection {fn deref_mut(&mut self)->&mut Self::Target{self.inner.as_mut().unwrap()}}
impl Drop for ObservedConnection {
 fn drop(&mut self){
  let hold=micros(self.start.elapsed());let q=self.query.as_ref().map(|q|q.lock().unwrap());
  record(self.phase.clone(),|r|{r.n+=1;r.acquire_us+=self.acquire_us;r.hold_us+=hold;if let Some(q)=q.as_ref(){r.samples+=1;r.sample_hold_us+=hold;r.queries+=q.queries;r.sql_us+=q.sql_us;r.commit_us+=q.commit_us;r.begin_us+=q.begin_us;}});
 }
}
struct Signal { parent:Waker, first:Option<Instant> }
struct WakeSignal(Mutex<Signal>);
impl Wake for WakeSignal {
 fn wake(self:Arc<Self>){self.wake_by_ref()}
 fn wake_by_ref(self:&Arc<Self>){let mut s=self.0.lock().unwrap();s.first.get_or_insert_with(Instant::now);s.parent.wake_by_ref();}
}
pub struct Profile<F> { future:Pin<Box<F>>,signal:Option<Arc<WakeSignal>>,start:Instant,last_end:Instant,poll_us:u64,ready_us:u64,phase:&'static str,sampled:bool }
pub fn profile<F:Future>(phase:&'static str,future:F)->Profile<F>{let now=Instant::now();Profile{future:Box::pin(future),signal:None,start:now,last_end:now,poll_us:0,ready_us:0,phase,sampled:SAMPLE.fetch_add(1,Ordering::Relaxed).is_multiple_of(32)}}
impl<F:Future> Future for Profile<F>{type Output=F::Output;fn poll(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<Self::Output>{
 let this=self.get_mut();if !this.sampled{return this.future.as_mut().poll(cx)}
 let start=Instant::now();
 if this.signal.is_none(){this.ready_us+=micros(start.duration_since(this.start));this.signal=Some(Arc::new(WakeSignal(Mutex::new(Signal{parent:cx.waker().clone(),first:None}))));}
 let signal=this.signal.as_ref().unwrap();{let mut s=signal.0.lock().unwrap();if let Some(wake)=s.first.take(){this.ready_us+=micros(start.duration_since(wake.max(this.last_end)));}s.parent=cx.waker().clone();}
 let waker=Waker::from(signal.clone());let mut context=Context::from_waker(&waker);let r=this.future.as_mut().poll(&mut context);
 this.last_end=Instant::now();this.poll_us+=micros(this.last_end.duration_since(start));
 if r.is_ready(){record(this.phase.to_owned(),|v|{v.n+=1;v.poll_us+=this.poll_us;v.ready_us+=this.ready_us;v.elapsed_us+=micros(this.start.elapsed());});}r
}}

