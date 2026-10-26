(function(){
  document.querySelectorAll('button.copy').forEach(function(b){
    b.addEventListener('click',function(){
      var pre=b.closest('.code').querySelector('pre');
      var t=pre?pre.innerText:'';
      (navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(function(){b.textContent='Copied';setTimeout(function(){b.textContent='Copy'},1400)}).catch(function(){b.textContent='Select & copy'});
    });
  });
  var m=document.querySelector('.menu'); if(m){m.addEventListener('click',function(){document.body.classList.toggle('nav-open')})}
  var lb=document.createElement('div'); lb.className='lightbox'; lb.setAttribute('role','dialog'); lb.setAttribute('aria-label','Enlarged figure');
  var im=document.createElement('img'); lb.appendChild(im); document.body.appendChild(lb);
  lb.addEventListener('click',function(){lb.classList.remove('on')});
  document.addEventListener('keydown',function(e){if(e.key==='Escape')lb.classList.remove('on')});
  document.querySelectorAll('a.zoom').forEach(function(a){a.addEventListener('click',function(e){e.preventDefault();im.src=a.getAttribute('href');im.alt=(a.querySelector('img')||{}).alt||'';lb.classList.add('on')})});
  var links=[].slice.call(document.querySelectorAll('.toc a'));
  if(links.length&&'IntersectionObserver' in window){
    var map={}; links.forEach(function(l){map[l.getAttribute('href').slice(1)]=l});
    var io=new IntersectionObserver(function(es){es.forEach(function(en){if(en.isIntersecting){links.forEach(function(l){l.classList.remove('on')}); var l=map[en.target.id]; if(l)l.classList.add('on')}})},{rootMargin:'-70px 0px -70% 0px'});
    document.querySelectorAll('h2[id]').forEach(function(h){io.observe(h)});
  }
})();
