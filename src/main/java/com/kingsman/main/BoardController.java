package com.kingsman.main;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.kingsman.service.BoardService;
import com.kingsman.vo.BoardVO;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@CrossOrigin(origins = "*")
@RestController("boardController")
public class BoardController {
	@Autowired
	private BoardService boardService;

	@PostMapping("/board")
	public Map boardInsert(@RequestBody BoardVO board) {
		this.boardService.insertBoard(board);
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("code", "success");
		return map;
	}

	@GetMapping("/board")
	public Map boardSelectAll() {
		Map<String, Object> map = new HashMap<String, Object>();
		this.boardService.selectAllBoards(map);
		List<BoardVO> list = (List<BoardVO>) map.get("boardResults");
		// list.forEach(board -> log.info("" +board));
		map.put("code", "success");

		return map;
	}

	@DeleteMapping("/board/{bnum}")
	public Map boardDelete(@PathVariable("bunm") int bnum) {
		log.info("삭제할 댓글 : {}", bnum);
		this.boardService.deleteBoard(bnum);
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("code", "success");
		return map;
	}

}
