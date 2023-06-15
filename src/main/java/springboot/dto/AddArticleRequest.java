package springboot.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import springboot.domain.Article;

@AllArgsConstructor
@NoArgsConstructor
@Getter
public class AddArticleRequest {

	private String title;
	private String content;

	public Article toEntity(String author) {
		return Article.builder()
			.title(title)
			.content(content)
			.author(author)
			.build();
	}
}

