var total_section = 0; // 전체 원페이지 수
var current_idx = 0;
var screen_h = 0; // 화면 높이
var page_h = 0;
var last_y = 0; // 스크롤 마지막 하단 높이
var onpage_on = true;


$(function() {
  var welcomeSection = $(".welcome-section"),
    enterButton = welcomeSection.find(".enter-button");

  setTimeout(function() {
    welcomeSection.removeClass("content-hidden");
  }, 800);
  enterButton.on("click", function(e) {
    e.preventDefault();
    welcomeSection.fadeOut();
    $("div").animate({
      width: "800px",
      height: "400px",
      opacity: 1
    },
    1000,
    function() {
      location.href = "./main.html";
    });
  });

  init();
 
});

$(window).resize(function() {
  // 반응형
  setHeight();
});

function init() {

  setHeight();

  total_section = $("#onepage > section").length;
  last_y = page_h * total_section;
}

function setHeight() {
  // 높이 설정
  screen_h = document.body.clientHeight;
  page_h = screen_h;
  $("#onepage > section").height(page_h);
}
